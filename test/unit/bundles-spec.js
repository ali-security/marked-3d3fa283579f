const fs = require('fs');
const path = require('path');
const srcRules = require('../../src/rules.js');
const cubicDef = require('../specs/redos/cubic_def.js');

const rootDir = path.resolve(__dirname, '..', '..');
const redosDir = path.resolve(__dirname, '..', 'specs', 'redos');

// Every regex and template in a rule set, keyed by its dotted path, so that two
// grammars can be compared with a diff that names whatever drifted apart.
function flattenGrammar(rules, prefix, flat) {
  prefix = prefix || '';
  flat = flat || {};

  Object.keys(rules).forEach(key => {
    const value = rules[key];
    const name = prefix ? `${prefix}.${key}` : key;

    if (value instanceof RegExp || typeof value === 'string') {
      flat[name] = `${value}`;
    } else if (value && typeof value === 'object') {
      flattenGrammar(value, name, flat);
    }
  });

  return flat;
}

// lib/marked.esm.js is an ES module, so it cannot be require()d from a CommonJS
// spec on the supported node versions. It is a self contained bundle whose only
// module level syntax is a single trailing `export default`, so swap that for a
// `return` and evaluate the bundle to reach the same export.
function loadEsmBundle() {
  const source = fs.readFileSync(path.resolve(rootDir, 'lib', 'marked.esm.js'), 'utf8');
  const body = source.replace(/\nexport default (\w+);/, '\nreturn $1;');

  if (body === source) {
    throw new Error('lib/marked.esm.js no longer ends with a single `export default`');
  }

  // eslint-disable-next-line no-new-func
  return new Function(`'use strict';\n${body}`)();
}

// The grammar is duplicated into every pre-built bundle shipped by
// package.json#files, and no build step regenerates them from src. `main`
// (src/marked.js) is covered by the rest of the suite, but nothing else loads
// these, so they get their own coverage here. marked.min.js is deliberately
// absent: it is minified output that cannot be maintained by hand, so it is
// left byte for byte as released rather than half updated.
const bundles = {
  'lib/marked.js': () => require('../../lib/marked.js'),
  'lib/marked.esm.js': loadEsmBundle
};

function fixture(name) {
  return fs.readFileSync(path.resolve(redosDir, name), 'utf8');
}

// Inputs that send an unpatched grammar into catastrophic backtracking.
const payloads = [
  {
    name: 'reference link (CVE-2022-21681)',
    markdown: fixture('reflink_redos.md'),
    html: fixture('reflink_redos.html')
  },
  {
    name: 'link definition (CVE-2022-21680)',
    markdown: cubicDef.markdown,
    html: cubicDef.html
  },
  {
    name: 'collapsed reference link',
    markdown: fixture('redos_nolink.md'),
    html: fixture('redos_nolink.html')
  }
];

describe('shipped bundles', () => {
  Object.keys(bundles).forEach(bundle => {
    describe(bundle, () => {
      let marked;

      beforeEach(() => {
        marked = bundles[bundle]();
        marked.setOptions(marked.getDefaults());
      });

      it('should expose the marked api', () => {
        expect(typeof marked).toBe('function');
        expect(typeof marked.lexer).toBe('function');
        expect(typeof marked.parser).toBe('function');
      });

      // The bundles are pre-built and committed, so nothing regenerates them
      // from src/rules.js. Compare the grammar they actually compile against
      // the source of truth, which pins every hardened regex in place.
      it('should compile the same grammar as src/rules.js', () => {
        expect(flattenGrammar(marked.Lexer.rules)).toEqual(flattenGrammar(srcRules));
      });

      payloads.forEach(payload => {
        it(`should not backtrack on a malicious ${payload.name}`, async() => {
          const before = process.hrtime();
          const actual = marked(payload.markdown, { silent: true });
          const elapsed = process.hrtime(before);

          await expectAsync(actual).toEqualHtml(payload.html);

          if (elapsed[0] > 0) {
            const seconds = (elapsed[0] + elapsed[1] * 1e-9).toFixed(3);
            fail(`took too long: ${seconds}s`);
          }
        });
      });
    });
  });
});
