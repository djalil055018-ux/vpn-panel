import type {
  SVGProps,
} from "react";

export type NavIconName =
  | "dashboard"
  | "nodes"
  | "deployments"
  | "core"
  | "recovery"
  | "settings"
  | "clients"
  | "shield"
  | "billing"
  | "activity"
  | "cascade"
  | "search";

type Props = {
  name: NavIconName;
} & SVGProps<SVGSVGElement>;

export function NavIcon({
  name,
  ...props
}: Props) {
  const common = {
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.8,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true,
  };

  const paths: Partial<Record<NavIconName, React.ReactNode>> = {
    cascade: <><rect x="2" y="3" width="7" height="7" rx="2"/><rect x="15" y="14" width="7" height="7" rx="2"/><path d="M9 6h6a4 4 0 0 1 4 4v4M5 10v4a4 4 0 0 0 4 4h6m1-7 3 3 3-3"/></>,
    search: <><circle cx="10" cy="10" r="6"/><path d="m15 15 6 6"/></>,
    clients: <><circle cx="9" cy="8" r="3" /><path d="M3 21v-3a6 6 0 0 1 12 0v3M16 5a3 3 0 0 1 0 6m3 10v-3a6 6 0 0 0-2-4" /></>,
    shield: <><path d="m12 3 8 3v6c0 4-4 7-8 9-4-2-8-5-8-9V6Z" /><path d="m8 12 3 3 5-6" /></>,
    billing: <><rect x="3" y="5" width="18" height="14" rx="3" /><path d="M3 10h18M7 15h3" /></>,
    activity: <><path d="M3 12h4l3-8 4 16 3-8h4" /></>,
  };
  if (paths[name]) return <svg {...common} {...props}>{paths[name]}</svg>;

  if (name === "dashboard") {
    return (
      <svg
        {...common}
        {...props}
      >
        <rect
          x="3"
          y="3"
          width="7"
          height="7"
          rx="1.5"
        />
        <rect
          x="14"
          y="3"
          width="7"
          height="7"
          rx="1.5"
        />
        <rect
          x="3"
          y="14"
          width="7"
          height="7"
          rx="1.5"
        />
        <rect
          x="14"
          y="14"
          width="7"
          height="7"
          rx="1.5"
        />
      </svg>
    );
  }

  if (name === "nodes") {
    return (
      <svg
        {...common}
        {...props}
      >
        <rect
          x="4"
          y="3"
          width="16"
          height="7"
          rx="2"
        />
        <rect
          x="4"
          y="14"
          width="16"
          height="7"
          rx="2"
        />
        <path d="M8 6.5h.01" />
        <path d="M8 17.5h.01" />
        <path d="M12 6.5h5" />
        <path d="M12 17.5h5" />
      </svg>
    );
  }

  if (name === "deployments") {
    return (
      <svg
        {...common}
        {...props}
      >
        <path d="M12 3v12" />
        <path d="m7 10 5 5 5-5" />
        <path d="M5 21h14" />
        <path d="M7 18h10" />
      </svg>
    );
  }

  if (name === "core") {
    return (
      <svg
        {...common}
        {...props}
      >
        <rect
          x="7"
          y="7"
          width="10"
          height="10"
          rx="2"
        />
        <path d="M9 1v3" />
        <path d="M15 1v3" />
        <path d="M9 20v3" />
        <path d="M15 20v3" />
        <path d="M20 9h3" />
        <path d="M20 14h3" />
        <path d="M1 9h3" />
        <path d="M1 14h3" />
        <path d="M10 10h4v4h-4z" />
      </svg>
    );
  }

  if (name === "recovery") {
    return (
      <svg
        {...common}
        {...props}
      >
        <path d="M3 12a9 9 0 1 0 3-6.7" />
        <path d="M3 4v6h6" />
        <path d="M12 7v5l3 2" />
      </svg>
    );
  }

  return (
    <svg
      {...common}
      {...props}
    >
      <circle
        cx="12"
        cy="12"
        r="3"
      />
      <path d="M19.4 15a1.7 1.7 0 0 0 .34 1.88l.06.06-2.83 2.83-.06-.06A1.7 1.7 0 0 0 15 19.4a1.7 1.7 0 0 0-1 .6 1.7 1.7 0 0 0-.4 1.1V21h-4v-.1a1.7 1.7 0 0 0-1.4-1.6 1.7 1.7 0 0 0-1.8.4l-.07.07-2.83-2.83.07-.07A1.7 1.7 0 0 0 4 15a1.7 1.7 0 0 0-.6-1 1.7 1.7 0 0 0-1.1-.4H2v-4h.3A1.7 1.7 0 0 0 4 8.2a1.7 1.7 0 0 0-.4-1.8l-.07-.07L6.36 3.5l.07.07A1.7 1.7 0 0 0 8.2 4a1.7 1.7 0 0 0 1-.6 1.7 1.7 0 0 0 .4-1.1V2h4v.3A1.7 1.7 0 0 0 15 4a1.7 1.7 0 0 0 1.8-.4l.07-.07 2.83 2.83-.07.07A1.7 1.7 0 0 0 20 8.2a1.7 1.7 0 0 0 .6 1 1.7 1.7 0 0 0 1.1.4H22v4h-.3A1.7 1.7 0 0 0 20 15z" />
    </svg>
  );
}
