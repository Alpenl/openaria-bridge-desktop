export function toast(message: string, tone: "success" | "danger"): void {
  const stack = document.getElementById("toastStack");
  if (!stack) return;
  const node = document.createElement("div");
  node.className = "toast";
  node.dataset.tone = tone;
  node.innerHTML = `<span class="dot"></span><span></span>`;
  (node.lastElementChild as HTMLElement).textContent = message;
  stack.appendChild(node);
  setTimeout(() => node.remove(), 2900);
}
