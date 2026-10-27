// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

import { BrowserRouter, Route, Routes } from "react-router-dom";
import { AuthGate } from "./auth";
import { Layout } from "./components/Layout";
import { Overview } from "./routes/Overview";
import { Events } from "./routes/Events";
import { EventDetail } from "./routes/EventDetail";
import { Alerts } from "./routes/Alerts";
import { Inventory } from "./routes/Inventory";
import { Rules } from "./routes/Rules";
import { Users } from "./routes/Users";
import { Tokens } from "./routes/Tokens";
import { Audit } from "./routes/Audit";
import { Compliance } from "./routes/Compliance";
import { Account } from "./routes/Account";

export function App() {
  return (
    <AuthGate>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<Overview />} />
            <Route path="events" element={<Events />} />
            <Route path="events/:id" element={<EventDetail />} />
            <Route path="alerts" element={<Alerts />} />
            <Route path="inventory" element={<Inventory />} />
            <Route path="rules" element={<Rules />} />
            <Route path="users" element={<Users />} />
            <Route path="tokens" element={<Tokens />} />
            <Route path="audit" element={<Audit />} />
            <Route path="compliance" element={<Compliance />} />
            <Route path="account" element={<Account />} />
            <Route path="*" element={<Overview />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthGate>
  );
}
