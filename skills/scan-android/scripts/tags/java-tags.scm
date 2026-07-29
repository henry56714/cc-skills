; java-tags.scm — tree-sitter tags 查询（def/ref 抽取）。
; 来源：改编自 Aider (Apache-2.0) 的 tree-sitter-language-pack/java-tags.scm。
; repo_map.py 用它把 Java 源节点标为「定义」(@definition.*) 或「引用」(@reference.*)。
; @name 捕获符号名；@definition.* / @reference.* 标注该处的角色。

(class_declaration
  name: (identifier) @name.definition.class) @definition.class

(interface_declaration
  name: (identifier) @name.definition.interface) @definition.interface

(enum_declaration
  name: (identifier) @name.definition.class) @definition.class

(method_declaration
  name: (identifier) @name.definition.method) @definition.method

(constructor_declaration
  name: (identifier) @name.definition.method) @definition.method

; ---- 引用 ----

(method_invocation
  name: (identifier) @name.reference.method) @reference.call

(object_creation_expression
  type: (type_identifier) @name.reference.class) @reference.class

(superclass
  (type_identifier) @name.reference.class) @reference.class

(super_interfaces
  (type_list
    (type_identifier) @name.reference.interface)) @reference.implementation
