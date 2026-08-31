type InvestigationBannerProps =
  | { variant: "investigating"; target: string }
  | { variant: "error"; target: string; message: string; onRetry: () => void; onDismiss: () => void };

/**
 * A slim overlay banner shown while a *new* investigation is running or has
 * failed, without hiding the dashboard already on screen -- searching a new
 * target should never make the existing graph/panels disappear, only the
 * very first load (before any data exists at all) has nothing to overlay.
 */
export function InvestigationBanner(props: InvestigationBannerProps) {
  if (props.variant === "investigating") {
    return (
      <div className="investigation-banner investigation-banner-loading" role="status">
        <div className="investigation-banner-bar">
          <div className="investigation-banner-bar-fill" />
        </div>
        <span className="investigation-banner-text">
          Investigating <strong>{props.target}</strong>&hellip;
        </span>
      </div>
    );
  }

  return (
    <div className="investigation-banner investigation-banner-error" role="alert">
      <span className="investigation-banner-text">
        Investigation of <strong>{props.target}</strong> failed: {props.message}
      </span>
      <div className="investigation-banner-actions">
        <button className="investigation-banner-retry" onClick={props.onRetry}>
          Retry
        </button>
        <button className="investigation-banner-dismiss" onClick={props.onDismiss} aria-label="Dismiss">
          ×
        </button>
      </div>
    </div>
  );
}
