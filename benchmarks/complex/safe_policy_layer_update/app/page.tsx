import { renameTask } from "./actions";

type Props = {
  params: { workspaceId: string };
};

export default function Page({ params }: Props) {
  const action = renameTask.bind(null, params.workspaceId);

  return (
    <form action={action}>
      <input type="hidden" name="taskId" value="task_123" />
      <input name="title" />
      <button type="submit">Rename</button>
    </form>
  );
}
