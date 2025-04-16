// eslint.config.js
import js from "@eslint/js";
import globals from "globals";

export default [
  // 1. Apply recommended rules globally
  js.configs.recommended,

  // 2. Configuration for your source and root JS files
  {
    files: ["src/**/*.js", "*.js"], // Apply to JS files in src and root
    languageOptions: {
      ecmaVersion: "latest", // Use modern ECMAScript
      sourceType: "module", // Use ES Modules
      globals: {
        ...globals.browser, // Define browser environment globals (like `atob`, `TextEncoder`)
        ...globals.node, // Define Node.js environment globals (like `process`)
        // Add any other specific globals your code might use directly
      },
    },
    rules: {
      // Your previous custom rules:
      "no-unused-vars": ["warn", { argsIgnorePattern: "^_" }],
      "no-prototype-builtins": "off",
      // Add any other project-specific rules here
    },
  },

  // 3. Configuration specifically for Jest test files
  {
    files: ["**/*.test.js"], // Match your test files
    languageOptions: {
      globals: {
        ...globals.jest, // Define Jest globals (describe, test, expect, etc.)
      },
    },
    // You could add rules from eslint-plugin-jest here if you install it
  },

  // 4. Define ignored files/directories
  {
    ignores: [
      "dist/**", // Ignore the build output directory
      "node_modules/**", // Generally good practice to ignore node_modules explicitly
    ],
  },
];
