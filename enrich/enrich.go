package enrich

// 组件时代不再需要网络资产富化（DNS 解析 / HTTP 指纹回填）：组件行来自固件解包，
// 没有域名或 URL 可以富化。保留同名空实现，避免上层调用点大改。

type Engine struct{}

func New(_ interface{}, _ interface{}, _ int) *Engine { return &Engine{} }

func (e *Engine) ResolveDomain(_ int64, _ string) {}

func (e *Engine) ProbeSite(_ int64, _ string)     {}

func (e *Engine) Close()                          {}
