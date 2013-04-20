#ifndef JAIL_RANGE_TREE_H
#define JAIL_RANGE_TREE_H

#include <algorithm>
#include <set>
#include <utility>

template<class T>
class range_tree {
 public:
  typedef typename std::set<std::pair<T, T> >::iterator iterator;

  range_tree() :sz(0) {
  }

  /* Add [lo, hi) to range. */
  void add(T lo, T hi) {
    iterator se, i = st.lower_bound(std::make_pair(lo, -1));
    if(i != st.begin()) {
      iterator j = i; --j;
      if(lo <= j->second) {
        lo = (--i)->first;
      }
    }
    for(se = i; i != st.end() && i->first <= hi; ++i) {
      sz -= i->second - i->first;
      hi = std::max(hi, i->second);
    }
    sz += hi - lo;
    st.erase(se, i);
    st.insert(std::make_pair(lo, hi));
  }

  /* Remove [lo, hi) from range. */
  void rem(T lo, T hi) {
    iterator se, i = st.lower_bound(std::make_pair(lo, 0));
    if(i != st.begin()) {
      iterator j = i; --j;
      T jhi = j->second;

      sz += j->second;
      *(T*)&j->second = std::min(jhi, lo);
      sz -= j->second;

      if(jhi > hi) {
        sz += jhi - hi;
        st.insert(std::make_pair(hi, jhi));
        return;
      }
    }
    for(se = i; i != st.end() && i->second <= hi; ++i) {
      sz -= i->second - i->first;
    }
    if(i != st.end()) {
      sz += i->first;
      *(T*)&i->first = std::max(i->first, hi);
      sz -= i->first;
    }
    st.erase(se, i);
  }

  iterator begin() {
    return st.begin();
  }

  iterator end() {
    return st.end();
  }

  void clear() {
    st.clear();
    sz = 0;
  }

  T size() {
    return sz;
  }

 private:
  T sz;
  std::set<std::pair<T, T> > st;
};

#endif // JAIL_RANGE_TREE_H
