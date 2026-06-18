package merger

// UnionFind 并查集
type UnionFind struct {
	parent map[string]string
}

// NewUnionFind 创建并查集
func NewUnionFind(items []string) *UnionFind {
	parent := make(map[string]string, len(items))
	for _, item := range items {
		parent[item] = item
	}
	return &UnionFind{parent: parent}
}

// Find 查找根节点
func (uf *UnionFind) Find(item string) string {
	parent, ok := uf.parent[item]
	if !ok {
		return item
	}
	if parent != item {
		uf.parent[item] = uf.Find(parent)
	}
	return uf.parent[item]
}

// Union 合并两个集合
func (uf *UnionFind) Union(left, right string) {
	leftRoot := uf.Find(left)
	rightRoot := uf.Find(right)
	if leftRoot != rightRoot {
		uf.parent[rightRoot] = leftRoot
	}
}

// Groups 获取所有分组
func (uf *UnionFind) Groups() map[string][]string {
	grouped := make(map[string][]string)
	for item := range uf.parent {
		root := uf.Find(item)
		grouped[root] = append(grouped[root], item)
	}
	return grouped
}
