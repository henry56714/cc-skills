; kotlin-tags.scm — tree-sitter tags 查询（def/ref 抽取）。
; Android Kotlin 专用 tags，避免只覆盖 Java 而漏掉 Kotlin 声明与调用。
; 节点名对应 fwcd/tree-sitter-kotlin 语法（class_declaration / function_declaration /
; object_declaration / property_declaration / call_expression / constructor_invocation）。
; @name 捕获符号名；@definition.* / @reference.* 标注角色。与 java-tags.scm 同形，供 repo_map 统一处理。

(class_declaration
  (type_identifier) @name.definition.class) @definition.class

(object_declaration
  (type_identifier) @name.definition.class) @definition.class

(function_declaration
  (simple_identifier) @name.definition.method) @definition.method

(property_declaration
  (variable_declaration
    (simple_identifier) @name.definition.constant)) @definition.constant

(enum_entry
  (simple_identifier) @name.definition.constant) @definition.constant

(type_alias
  (type_identifier) @name.definition.type) @definition.type

; ---- 引用 ----

; 直接调用 foo(...)
(call_expression
  (simple_identifier) @name.reference.method) @reference.call

; 成员调用 x.foo(...)：导航表达式的后缀标识符
(call_expression
  (navigation_expression
    (navigation_suffix
      (simple_identifier) @name.reference.method))) @reference.call

; 构造调用 Foo(...)
(constructor_invocation
  (user_type
    (type_identifier) @name.reference.class)) @reference.class

; 继承/委托的父类型
(delegation_specifier
  (user_type
    (type_identifier) @name.reference.class)) @reference.class
