#include <list>
#include <utility>

template<typename T>
class memory_allocator {
 public:
  typedef typename std::list<std::pair<T*, size_t> >::iterator iter;

  memory_allocator() : A(NULL), N(0), own(false) {
  }

  memory_allocator(size_t N) : own(true) {
    A = reinterpret_cast<T*>(malloc(sizeof(T) * N));
    regions.push_back(std::make_pair(A, N));
  }

  memory_allocator(T* A, size_t N) : A(A), N(N), own(false) {
    regions.push_back(std::make_pair(A, N));
  }

  ~memory_allocator() {
    if(own) {
      ::free(A);
    }
  }

  void reset(T* A, size_t N) {
    if(own) {
      ::free(A);
    }
    this->A = A;
    this->N = N;
    own = false;
    regions.clear();
    regions.push_back(std::make_pair(A, N));
  }

  T* allocate(size_t N) {
    for(iter it = regions.begin(), e = regions.end(); it != e; ++it) {
      if(N == it->second) {
        regions.erase(it);
      } else if(N < it->second) {
        it->second -= N;
        return it->first + it->second - N;
      }
    }
    return NULL;
  }

  T* allocate_largest(size_t* N) {
    iter jt = regions.end();
    for(iter it = regions.begin(), e = jt; it != e; ++it) {
      if(jt == regions.end() || jt->second < it->second) {
        jt = it;
      }
    }

    T* result = jt->first;
    if(N) *N = jt->second;
    regions.erase(jt);
    return result;
  }

  void free(T* base, size_t N) {
    for(iter it = regions.begin(), e = regions.end(); it != e; ++it) {
      if(base <= it->first + it->second) {
        base = std::min(base, it->first);

        iter jt;
        for(jt = it; jt != e && jt->first <= base + N; jt++) {
          N = std::max(N, (jt->first - base) + jt->second);
        }
        regions.insert(regions.erase(it, jt), std::make_pair(base, N));
        return;
      }
    }
    regions.push_back(std::make_pair(base, N));
    
  }

  const T* address() const {
    return A;
  }

  size_t size() const {
    return N;
  }

 private:
  T* A;
  size_t N;
  bool own;

  std::list<std::pair<T*, size_t> > regions;
};
