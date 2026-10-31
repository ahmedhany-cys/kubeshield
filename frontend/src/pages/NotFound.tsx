import { Link } from 'react-router-dom'
import { EmptyState } from '../components/EmptyState'

export default function NotFoundPage() {
  return (
    <EmptyState
      title="Page not found"
      description="The page you requested does not exist."
      action={
        <Link to="/" className="link text-[13px]">
          Back to overview
        </Link>
      }
    />
  )
}
