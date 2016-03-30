package utils

// 实现一个可以排序的Map

type Map struct {
    Key   uint32
    Value string
}

type MapSort []Map

func NewMapSort(m map[uint32]string) MapSort {
    ms := make(MapSort, len(m))
    for k, v := range m {
        ms = append(ms, Map{Key: k, Value: v})
    }

    return ms
}

func (this MapSort) Len() int {
    return len(this)
}

func (this MapSort) Less(i, j int) bool {
    return this[i].Key < this[j].Key
}

func (this MapSort) Swap(i, j int) {
    this[i], this[j] = this[j], this[i]
}
