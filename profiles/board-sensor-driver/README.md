<!-- SPDX-License-Identifier: Apache-2.0 -->
# board-sensor-driver

Kind `profile`. Adds one opt-in task that writes a `modules-load.d` entry when the board's
product name is on `board_sensor_driver_boards`. Extend the list in your own overlay by
enabling the profile and overriding the variable with an `override` customization, not by
editing this file. Proposed upstream as a board-quirk table; retire this when it lands.
