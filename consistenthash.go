package utils

// 实现一致性哈希算法

import (
	"encoding/hex"
	"fmt"
	"sort"
)

type ConsistentHash struct {
	replicas  uint32              // 模拟节点数
	Targets   map[string][]uint32 // 所有节点map
	Positions MapSort             // 位置节点map
	targetNum uint32              // 节点数
	circle    uint32              // 分布圆的大小
}

// 初始化一个ConsistentHash
// @param num 虚拟节点数
func NewConsistentHash(num uint32, circleSize ...uint32) *ConsistentHash {
	if num == 0 {
		// 默认节点数
		num = 64
	}

	var circle uint32
	if len(circleSize) > 0 {
		circle = circleSize[0]
	} else {
		circle = 1<<32 - 1
	}

	return &ConsistentHash{replicas: num, Targets: make(map[string][]uint32),
		Positions: NewMapSort(make(map[uint32]string)), circle: circle}
}

// 添加一个节点
func (this *ConsistentHash) AddTarget(target string) {
	var i uint32
	i = 0
	for i < this.replicas {
		t := fmt.Sprintf("%s%s", target, string(i))
		position := this.hash(t)
		this.Targets[target] = append(this.Targets[target], position)
		this.Positions = append(this.Positions, Map{Key: position, Value: target})
		i++
	}
	this.targetNum++
	// 对位置map排序
	sort.Sort(this.Positions)
}

// 删除节点
func (this *ConsistentHash) RemoveTarget(target string) {
	s := MapSort{}
	for _, v := range this.Targets[target] {
		for key, value := range this.Positions {
			if value.Key != v {
				s = append(s, this.Positions[key])
			}
		}
	}
	delete(this.Targets, target)

	this.targetNum--

	this.Positions = s
}

// 查找节点
func (this *ConsistentHash) LookupTarget(resource string) string {
	p := this.hash(resource)

	// 计算v应该存放到哪个节点上去
	// 用二分法去检查在那个target上
	return this.dichotomieSearch(this.Positions, p)
}

// 二分法查找大于节点最近的节点
func (this *ConsistentHash) dichotomieSearch(list MapSort, k uint32) string {
	num := len(list)
	half := num / 2

	var target string
	switch {
	case k <= list[0].Key || k > list[num-1].Key:
		// 在开始节点和结束节点之间
		target = list[0].Value
	case k == list[num-1].Key:
		// 正好是结束点
		target = list[num-1].Value
	case list[half].Key == k || (k > list[half-1].Key && k < list[half].Key):
		// 在一半和前一个节点间
		target = list[half].Value
	case k > list[half].Key && k < list[half+1].Key:
		// 在一半和下一个节点间
		target = list[half+1].Value
	case k < list[half].Key:
		// 那么在小的一半里面
		target = this.dichotomieSearch(list[0:half], k)
	case k > list[half].Key:
		// 在大的一半里面
		target = this.dichotomieSearch(list[half:], k)
	}

	return target
}

// 计算hash值
func (this *ConsistentHash) hash(key string) uint32 {
	// crc32 fnv 分布都不太均匀 md5f分布最好 adler32最差
	k := Md5Sum(key)
	ks := k[0:8]
	var i uint32
	i = 1
	ks = Reverse(ks)
	// 转换成数字
	b := make([]byte, 4)
	hex.Decode(b, []byte(ks))
	for _, v := range b {
		i *= uint32(v)
	}

	if i == this.circle {
		// 那么直接返回i
		return i
	}

	return i % this.circle
}
