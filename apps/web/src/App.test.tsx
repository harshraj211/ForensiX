import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { App } from "./App";

describe("App", () => {
  it("identifies the product and controlled triage mode", () => {
    render(<App />);

    expect(screen.getByRole("heading", { name: "ForensiX" })).toBeInTheDocument();
    expect(screen.getByText("Controlled Logical Triage Mode")).toBeInTheDocument();
  });
});
