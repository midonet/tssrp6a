module.exports = {
  parser: "@typescript-eslint/parser",
  plugins: ["@typescript-eslint"],

  env: {
    browser: true,
    es6: true,
    node: true,
  },

  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/eslint-recommended",
    "plugin:@typescript-eslint/recommended",
  ],

  rules: {
    "comma-dangle": ["error", "always-multiline"],
    "sort-imports": [
      "error",
      {
        ignoreDeclarationSort: true,
        ignoreMemberSort: true,
        memberSyntaxSortOrder: ["none", "all", "single", "multiple"],
      },
    ],

    "@typescript-eslint/explicit-module-boundary-types": "off",
    "@typescript-eslint/no-explicit-any": "off",
    "@typescript-eslint/no-inferrable-types": "off",
    "@typescript-eslint/no-non-null-assertion": "off",
    "@typescript-eslint/no-unused-vars": "off",
    "@typescript-eslint/no-var-requires": "off",
  },
};
