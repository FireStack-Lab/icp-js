# @ICP-JS packages

## packages
* icp-utils
* icp-cryptos

## Build from source files

### Install `lerna` and `typescript` globally

```bash
yarn global add lerna && yarn global add typescript
```
### Bootstrap and build

```bash
yarn bootstrap
```

### Bundle

build `umd` and `esm` version javascript for each sub-packages, which can be accessed by `import` or `require`

```bash 
yarn dist
```
All files are exported in `packages/dist` folder, use `**.esm.js` or `**.umd.js` format

