import {
  cloneElement,
  createContext,
  useCallback,
  useContext,
  useId,
  useEffect,
  useRef,
  useState,
  type ReactNode,
  type ReactElement,
} from 'react'
import { X, AlertCircle } from 'lucide-react'
function parseNumber(
  text: string,
  min: number | undefined,
  max: number | undefined,
): { value: number | undefined; valid: boolean } {
  const raw = text.trim()
  if (raw === '') return { value: undefined, valid: true }
  const value = Number(raw)
  if (!Number.isFinite(value) || !Number.isInteger(value)) return { value: undefined, valid: false }
  if ((min !== undefined && value < min) || (max !== undefined && value > max))
    return { value: undefined, valid: false }
  return { value, valid: true }
}
// NumberInput keeps what the user typed, including an empty or invalid draft,
// so deleting a value does not silently become zero. Invalid text turns the
// box red and is reported to the form, which must block submission.
export function NumberInput({
  id,
  value,
  onChange,
  onInvalid,
  min,
  max,
  required = false,
  placeholder,
  disabled = false,
  ariaLabel,
}: {
  id?: string
  value: number | undefined
  onChange: (value: number | undefined) => void
  onInvalid?: (invalid: boolean) => void
  min?: number
  max?: number
  required?: boolean
  placeholder?: string
  disabled?: boolean
  ariaLabel?: string
}) {
  const show = (n: number | undefined) => (n === undefined || !Number.isFinite(n) ? '' : String(n))
  const [text, setText] = useState(() => show(value))
  const emitted = useRef<number | undefined>(value)
  const parsed = parseNumber(text, min, max)
  const invalid = !parsed.valid || (required && parsed.value === undefined)
  const report = useRef(onInvalid)
  report.current = onInvalid
  // Reflect changes made outside this field (another object selected, a
  // discarded draft), but never rewrite the text the user is editing.
  useEffect(() => {
    if (Object.is(value, emitted.current)) return
    setText(show(value))
    emitted.current = value
  }, [value])
  useEffect(() => {
    const bad = !parseNumber(text, min, max).valid || (required && value === undefined)
    if (bad) report.current?.(true)
    return () => report.current?.(false)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  const update = (next: string) => {
    setText(next)
    const result = parseNumber(next, min, max)
    const bad = !result.valid || (required && result.value === undefined)
    report.current?.(bad)
    if (bad) return
    emitted.current = result.value
    onChange(result.value)
  }
  return (
    <input
      id={id}
      type="text"
      inputMode="numeric"
      autoComplete="off"
      aria-label={ariaLabel}
      aria-invalid={invalid || undefined}
      required={required}
      placeholder={placeholder}
      disabled={disabled}
      value={text}
      onChange={(event) => update(event.target.value)}
    />
  )
}
export function Badge({ children, tone = '' }: { children: ReactNode; tone?: string }) {
  return (
    <span className={`badge ${tone || String(children).toLowerCase()}`}>
      <i />
      {children}
    </span>
  )
}
export function Field({
  label,
  children,
}: {
  label: string
  children: ReactElement<{ id?: string }>
}) {
  const id = useId()
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {cloneElement(children, { id })}
    </div>
  )
}
export function ErrorBox({ children }: { children: ReactNode }) {
  return (
    <div role="alert" className="error">
      <AlertCircle size={17} />
      <span>{children}</span>
    </div>
  )
}
export function Modal({
  title,
  children,
  close,
}: {
  title: string
  children: ReactNode
  close: () => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    const d = ref.current!
    d.showModal()
    return () => d.close()
  }, [])
  return (
    <dialog
      ref={ref}
      onCancel={(e) => {
        e.preventDefault()
        close()
      }}
      aria-label={title}
    >
      <header>
        <h2>{title}</h2>
        <button className="icon" aria-label="Close dialog" onClick={close}>
          <X size={20} />
        </button>
      </header>
      {children}
    </dialog>
  )
}
export type ConfirmOptions = {
  title: string
  message: ReactNode
  confirmLabel?: string
  danger?: boolean
}
const ConfirmContext = createContext<(options: ConfirmOptions) => Promise<boolean>>(() =>
  Promise.resolve(false),
)
export const useConfirm = () => useContext(ConfirmContext)
// In-app replacement for window.confirm. Cancel has the initial focus, so a
// stray Enter or a click in the wrong place does not confirm.
export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<ConfirmOptions | null>(null)
  const resolvePending = useRef<((answer: boolean) => void) | null>(null)
  const ask = useCallback(
    (options: ConfirmOptions) =>
      new Promise<boolean>((resolve) => {
        // A second prompt cancels the one still waiting instead of stranding it.
        resolvePending.current?.(false)
        resolvePending.current = resolve
        setPending(options)
      }),
    [],
  )
  const settle = (answer: boolean) => {
    resolvePending.current?.(answer)
    resolvePending.current = null
    setPending(null)
  }
  return (
    <ConfirmContext.Provider value={ask}>
      {children}
      {pending && (
        <Modal title={pending.title} close={() => settle(false)}>
          <p>{pending.message}</p>
          <div className="modal-actions">
            <button type="button" onClick={() => settle(false)} autoFocus>
              Cancel
            </button>
            <button
              type="button"
              className={pending.danger ? 'danger' : 'primary'}
              onClick={() => settle(true)}
            >
              {pending.confirmLabel ?? 'Confirm'}
            </button>
          </div>
        </Modal>
      )}
    </ConfirmContext.Provider>
  )
}
