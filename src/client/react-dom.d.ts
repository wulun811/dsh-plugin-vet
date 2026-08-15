/**
 * react-dom 最小类型声明（vet 不依赖 @types/react-dom——DSH 运行时的 __ModuleLoader__ 提供 react-dom，
 * 此处仅声明 createPortal 供 typecheck 通过；构建时 react-dom 在 external 列表，由运行时解析）。
 */
declare module 'react-dom' {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  export function createPortal(
    children: any,
    container: Element | DocumentFragment,
    key?: string | null,
  ): any
}