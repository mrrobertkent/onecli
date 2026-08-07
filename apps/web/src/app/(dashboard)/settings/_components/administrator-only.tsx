import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@onecli/ui/components/card";

export interface AdministratorOnlyProps {
  what: string;
}

/** What a member sees where an administrator sees the surface. */
export const AdministratorOnly = ({ what }: AdministratorOnlyProps) => (
  <Card>
    <CardHeader>
      <CardTitle>Administrators only</CardTitle>
      <CardDescription>
        {what} is managed by an administrator of this instance. Ask one for the
        change you need.
      </CardDescription>
    </CardHeader>
  </Card>
);
