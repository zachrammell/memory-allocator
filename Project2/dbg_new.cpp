#include "Project2Helper.h"
#include "mallocator.h"
#include <cstdio>
#include <cstdlib>
#include <new>
#include <list>
#include <algorithm>

constexpr static const char* log_header { "[DBG HEAP]: " };

// kilobytes operator to make dealing with page sizes easier
constexpr std::size_t operator""k(std::size_t n)
{
  return n * 1024;
}

constexpr std::size_t operator""G(std::size_t n)
{
  return n * 1024 * 1024 * 1024;
}

struct VirtualBlock
{
  std::size_t page_count;
  std::size_t block_size;
  void* pages;
  VirtualBlock(std::size_t sz = 64k)
  : page_count{0},
    block_size{ sz / 64k + !!(sz % 64k) },
    pages{ VirtualAlloc(NULL, sz, MEM_RESERVE, PAGE_NOACCESS) }
  {
    if (!pages)
    {
      throw std::bad_alloc{};
    }
  }
  static bool unreasonable(std::size_t bytes)
  {
    return bytes > 2G;
  }
  bool canFit(std::size_t bytes) const
  {
    return bytes < (block_size - (page_count + 1) * 4k);
  }
  bool isFull(void) const
  {
    return page_count * 4k == 64k;
  }
  void* allocate(std::size_t bytes) 
  {
    if (canFit(bytes))
    {
      std::size_t pages_to_allocate = bytes / 4k + !!(bytes % 4k);
      void* p = VirtualAlloc((byte*)pages + (page_count * 4k), 4k * pages_to_allocate, MEM_COMMIT, PAGE_READWRITE);
      if (!p)
      {
        wchar_t buf[256];
        FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                       buf, (sizeof(buf) / sizeof(wchar_t)), NULL);
        std::wprintf(L"%ls\n", buf);
        DEBUG_BREAKPOINT();
      }
      page_count += pages_to_allocate + 1;
      return (byte*)p + (4k * pages_to_allocate - bytes);
    }
    return NULL;
  }
  void deallocate(void* mem, std::size_t sz) const
  {
    // C6250 intentional
    VirtualFree(mem, sz, MEM_DECOMMIT);
  }
};

enum AllocFlags
{
  SCALAR = 1 << 0,
  VECTOR = 1 << 1,
};

struct Allocation
{
  void* data;
  std::size_t size;
  std::uint32_t flags;
  VirtualBlock* vBlock;
};

static bool alloc_predicate(Allocation const& a1, Allocation const& a2)
{
  return a1.data > a2.data;
}

static std::list<Allocation, Mallocator<Allocation>> allocs;
static std::list<Allocation, Mallocator<Allocation>> deallocs;
static std::list<VirtualBlock, Mallocator<VirtualBlock>> virtualBlocks;

static void exit_cleanup(void);

struct alloc_return
{
  void* data;
  VirtualBlock* vBlock;
};

static alloc_return alloc(std::size_t sz);

void memdbg_init()
{
  atexit(exit_cleanup);
}

void* operator new(std::size_t sz)
{
  // std::printf("global op new called, size = %zu\n", sz);
  if (VirtualBlock::unreasonable(sz))
  {
    throw std::bad_alloc{};
  }
  alloc_return ret = alloc(sz);
  void* ptr = ret.data;
  if (ptr)
  {
    Allocation new_alloc{ ptr, sz, SCALAR, ret.vBlock };
    allocs.insert(
      std::upper_bound(allocs.begin(), allocs.end(), new_alloc, alloc_predicate),
      new_alloc
    );
    return ptr;
  }
  else
    throw std::bad_alloc{};
}

void* operator new(std::size_t sz, const std::nothrow_t&) NO_THROW
{
  // std::printf("global op new called, size = %zu\n", sz);
  if (VirtualBlock::unreasonable(sz))
  {
    return NULL;
  }
  alloc_return ret = alloc(sz);
  void* ptr = ret.data;
  if (ptr)
  {
    Allocation new_alloc{ ptr, sz, SCALAR, ret.vBlock };
    allocs.insert(
      std::upper_bound(allocs.begin(), allocs.end(), new_alloc, alloc_predicate),
      new_alloc
    );
    return ptr;
  }
  return ptr;
}

void* operator new[](std::size_t sz) 
{
  // std::printf("global op new[] called, size = %zu\n", sz);
  if (VirtualBlock::unreasonable(sz))
  {
    throw std::bad_alloc{};
  }
  alloc_return ret = alloc(sz);
  void* ptr = ret.data;
  if (ptr)
  {
    Allocation new_alloc{ ptr, sz, VECTOR, ret.vBlock };
    allocs.insert(
      std::upper_bound(allocs.begin(), allocs.end(), new_alloc, alloc_predicate),
      new_alloc
    );
    return ptr;
  }
  else
    throw std::bad_alloc{};
}

void* operator new[](std::size_t sz, const std::nothrow_t&) NO_THROW
{
  // std::printf("global op new[] called, size = %zu\n", sz);
  if (VirtualBlock::unreasonable(sz))
  {
    return NULL;
  }
  alloc_return ret = alloc(sz);
  void* ptr = ret.data;
  if (ptr)
  {
    Allocation new_alloc{ ptr, sz, VECTOR, ret.vBlock };
    allocs.insert(
      std::upper_bound(allocs.begin(), allocs.end(), new_alloc, alloc_predicate),
      new_alloc
    );
    return ptr;
  }
  return ptr;
}

void operator delete(void* addr)
{
  // std::printf("global op delete called, address = 0x%p\n", addr);
  if (!addr)
  {
    return;
  }
  Allocation dealloc { addr, 0, SCALAR };
  auto dealloc_found = std::lower_bound(deallocs.begin(), deallocs.end(), dealloc, alloc_predicate);
  if (dealloc_found != deallocs.end() && dealloc_found->data == addr)
  {
    std::fputs(log_header, stdout);
    std::puts("Scalar delete called on memory that was already deleted.");
    DEBUG_BREAKPOINT();
  }
  auto found = std::lower_bound(allocs.begin(), allocs.end(), dealloc, alloc_predicate);
  if (found == allocs.end())
  {
    std::fputs(log_header, stdout);
    std::puts("Scalar delete called on memory that was not allocated.");
    DEBUG_BREAKPOINT();
  }
  if (!(found->flags & SCALAR))
  {
    std::fputs(log_header, stdout);
    std::puts("Scalar delete called on non-scalar allocation.");
    DEBUG_BREAKPOINT();
  }
  if (found->size == 0)
  {
    std::free(addr);
    allocs.erase(found);
    return;
  }
  deallocs.push_back(*found);
  found->vBlock->deallocate(addr, found->size);
  allocs.erase(found);
}

void operator delete(void* addr, std::size_t size)
{
  // std::printf("global op delete called, size = %zu, address = 0x%p\n", size, addr);
  if (!addr)
  {
    return;
  }
  Allocation dealloc{ addr, size, SCALAR };
  auto dealloc_found = std::lower_bound(deallocs.begin(), deallocs.end(), dealloc, alloc_predicate);
  if (dealloc_found != deallocs.end() && dealloc_found->data == addr)
  {
    std::fputs(log_header, stdout);
    std::puts("Scalar delete called on memory that was already deleted.");
    DEBUG_BREAKPOINT();
  }
  auto found = std::lower_bound(allocs.begin(), allocs.end(), dealloc, alloc_predicate);
  if (found == allocs.end())
  {
    std::fputs(log_header, stdout);
    std::puts("Scalar delete called on memory that was not allocated.");
    DEBUG_BREAKPOINT();
  }
  if (!(found->flags & SCALAR))
  {
    std::fputs(log_header, stdout);
    std::puts("Scalar delete called on non-scalar allocation.");
    DEBUG_BREAKPOINT();
  }
  if (found->size != size)
  {
    std::fputs(log_header, stdout);
    std::puts("Scalar delete used with incorrect size.");
    DEBUG_BREAKPOINT();
  }
  if (found->size == 0)
  {
    std::free(addr);
    allocs.erase(found);
    return;
  }
  deallocs.push_back(*found);
  found->vBlock->deallocate(addr, found->size);
  allocs.erase(found);
}

void operator delete(void* addr, const std::nothrow_t&) NO_THROW
{
  // std::printf("global op delete called, address = 0x%p\n", addr);
  if (!addr)
  {
    return;
  }
  Allocation dealloc{ addr, 0, SCALAR };
  auto dealloc_found = std::lower_bound(deallocs.begin(), deallocs.end(), dealloc, alloc_predicate);
  if (dealloc_found != deallocs.end() && dealloc_found->data == addr)
  {
    std::fputs(log_header, stdout);
    std::puts("Scalar delete called on memory that was already deleted.");
    DEBUG_BREAKPOINT();
  }
  auto found = std::lower_bound(allocs.begin(), allocs.end(), dealloc, alloc_predicate);
  if (found == allocs.end())
  {
    std::fputs(log_header, stdout);
    std::puts("Scalar delete called on memory that was not allocated.");
    DEBUG_BREAKPOINT();
  }
  if (!(found->flags & SCALAR))
  {
    std::fputs(log_header, stdout);
    std::puts("Scalar delete called on non-scalar allocation.");
    DEBUG_BREAKPOINT();
  }
  if (found->size == 0)
  {
    std::free(addr);
    allocs.erase(found);
    return;
  }
  deallocs.push_back(*found);
  found->vBlock->deallocate(addr, found->size);
  allocs.erase(found);
}

void operator delete[](void* addr)
{
  // std::printf("global op delete[] called, address = 0x%p\n", addr);
  if (!addr)
  {
    return;
  }
  Allocation dealloc{ addr, 0, VECTOR };
  auto dealloc_found = std::lower_bound(deallocs.begin(), deallocs.end(), dealloc, alloc_predicate);
  if (dealloc_found != deallocs.end() && dealloc_found->data == addr)
  {
    std::fputs(log_header, stdout);
    std::puts("Vector delete called on memory that was already deleted.");
    DEBUG_BREAKPOINT();
  }
  auto found = std::lower_bound(allocs.begin(), allocs.end(), dealloc, alloc_predicate);
  if (found == allocs.end())
  {
    std::fputs(log_header, stdout);
    std::puts("Vector delete called on memory that was not allocated.");
    DEBUG_BREAKPOINT();
  }
  if (!(found->flags & VECTOR))
  {
    std::fputs(log_header, stdout);
    std::puts("Vector delete called on non-vector allocation.");
    DEBUG_BREAKPOINT();
  }
  if (found->size == 0)
  {
    std::free(addr);
    allocs.erase(found);
    return;
  }
  deallocs.push_back(*found);
  found->vBlock->deallocate(addr, found->size);
  allocs.erase(found);
}

void operator delete[](void* addr, std::size_t size)
{
  // std::printf("global op delete[] called, size = %zu, address = 0x%p\n", size, addr);
  if (!addr)
  {
    return;
  }
  Allocation dealloc{ addr, 0, VECTOR };
  auto dealloc_found = std::lower_bound(deallocs.begin(), deallocs.end(), dealloc, alloc_predicate);
  if (dealloc_found != deallocs.end() && dealloc_found->data == addr)
  {
    std::fputs(log_header, stdout);
    std::puts("Vector delete called on memory that was already deleted.");
    DEBUG_BREAKPOINT();
  }
  auto found = std::lower_bound(allocs.begin(), allocs.end(), dealloc, alloc_predicate);
  if (found == allocs.end())
  {
    std::fputs(log_header, stdout);
    std::puts("Vector delete called on memory that was not allocated.");
    DEBUG_BREAKPOINT();
  }
  if (!(found->flags & VECTOR))
  {
    std::fputs(log_header, stdout);
    std::puts("Vector delete called on non-vector allocation.");
    DEBUG_BREAKPOINT();
  }
  if (found->size != size)
  {
    std::fputs(log_header, stdout);
    std::puts("Vector delete used with incorrect size.");
    DEBUG_BREAKPOINT();
  }
  if (found->size == 0)
  {
    std::free(addr);
    allocs.erase(found);
    return;
  }
  deallocs.push_back(*found);
  found->vBlock->deallocate(addr, found->size);
  allocs.erase(found);
}

void operator delete[](void* addr, const std::nothrow_t&) NO_THROW
{
  // std::printf("global op delete[] called, address = 0x%p\n", addr);
  Allocation dealloc{ addr, 0, VECTOR };
  auto dealloc_found = std::lower_bound(deallocs.begin(), deallocs.end(), dealloc, alloc_predicate);
  if (dealloc_found != deallocs.end() && dealloc_found->data == addr)
  {
    std::fputs(log_header, stdout);
    std::puts("Vector delete called on memory that was already deleted.");
    DEBUG_BREAKPOINT();
  }
  auto found = std::lower_bound(allocs.begin(), allocs.end(), dealloc, alloc_predicate);
  if (found == allocs.end())
  {
    std::fputs(log_header, stdout);
    std::puts("Vector delete called on memory that was not allocated.");
    DEBUG_BREAKPOINT();
  }
  if (!(found->flags & VECTOR))
  {
    std::fputs(log_header, stdout);
    std::puts("Vector delete called on non-vector allocation.");
    DEBUG_BREAKPOINT();
  }
  if (found->size == 0)
  {
    std::free(addr);
    allocs.erase(found);
    return;
  }
  deallocs.push_back(*found);
  found->vBlock->deallocate(addr, found->size);
  allocs.erase(found);
}

static void exit_cleanup(void)
{
  if (!allocs.empty())
  {
    std::fputs(log_header, stdout);
    std::printf("%lu allocations leaked in %lu blocks.", allocs.size(), virtualBlocks.size());
    // TODO: more descriptive printing
    DEBUG_BREAKPOINT();
  }
}

static alloc_return alloc(std::size_t sz)
{
  if (!sz)
  {
    return { std::malloc(0), NULL };
  }
  if (!virtualBlocks.empty())
  {
    for (VirtualBlock& vb : virtualBlocks)
    {
      void* p = NULL;
      if (p = vb.allocate(sz))
      {
        return { p, &vb };
      }
    }
  }
  if (sz > 64k)
  {
    VirtualBlock& vb = virtualBlocks.emplace_back(VirtualBlock{ sz });
    return { vb.allocate(sz), &vb };
  }
  VirtualBlock& vb = virtualBlocks.emplace_back(VirtualBlock{});
  return { vb.allocate(sz), &vb };
}
