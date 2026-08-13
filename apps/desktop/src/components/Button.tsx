import type { ButtonHTMLAttributes, ReactNode } from 'react';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> { variant?: 'primary' | 'secondary' | 'quiet'; children: ReactNode }

export function Button({ variant = 'secondary', className = '', children, ...props }: ButtonProps) {
  return <button className={`button button--${variant} ${className}`.trim()} {...props}>{children}</button>;
}
