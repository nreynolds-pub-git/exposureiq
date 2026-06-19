import { api } from '../lib/api';
import type { FilterState } from '../lib/types';

interface Props {
  filters: FilterState;
}

export function ExportButtons({ filters }: Props) {
  return (
    <div className="flex gap-2">
      <a className="btn-secondary" href={api.exportUrl(filters, 'csv')}>
        Export CSV
      </a>
      <a className="btn-primary" href={api.exportUrl(filters, 'json')}>
        Export JSON
      </a>
    </div>
  );
}
