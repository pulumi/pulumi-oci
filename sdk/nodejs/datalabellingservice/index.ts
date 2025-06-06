// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export { DatasetArgs, DatasetState } from "./dataset";
export type Dataset = import("./dataset").Dataset;
export const Dataset: typeof import("./dataset").Dataset = null as any;
utilities.lazyLoad(exports, ["Dataset"], () => require("./dataset"));

export { GetAnnotationFormatArgs, GetAnnotationFormatResult, GetAnnotationFormatOutputArgs } from "./getAnnotationFormat";
export const getAnnotationFormat: typeof import("./getAnnotationFormat").getAnnotationFormat = null as any;
export const getAnnotationFormatOutput: typeof import("./getAnnotationFormat").getAnnotationFormatOutput = null as any;
utilities.lazyLoad(exports, ["getAnnotationFormat","getAnnotationFormatOutput"], () => require("./getAnnotationFormat"));

export { GetAnnotationFormatsArgs, GetAnnotationFormatsResult, GetAnnotationFormatsOutputArgs } from "./getAnnotationFormats";
export const getAnnotationFormats: typeof import("./getAnnotationFormats").getAnnotationFormats = null as any;
export const getAnnotationFormatsOutput: typeof import("./getAnnotationFormats").getAnnotationFormatsOutput = null as any;
utilities.lazyLoad(exports, ["getAnnotationFormats","getAnnotationFormatsOutput"], () => require("./getAnnotationFormats"));

export { GetDatasetArgs, GetDatasetResult, GetDatasetOutputArgs } from "./getDataset";
export const getDataset: typeof import("./getDataset").getDataset = null as any;
export const getDatasetOutput: typeof import("./getDataset").getDatasetOutput = null as any;
utilities.lazyLoad(exports, ["getDataset","getDatasetOutput"], () => require("./getDataset"));

export { GetDatasetsArgs, GetDatasetsResult, GetDatasetsOutputArgs } from "./getDatasets";
export const getDatasets: typeof import("./getDatasets").getDatasets = null as any;
export const getDatasetsOutput: typeof import("./getDatasets").getDatasetsOutput = null as any;
utilities.lazyLoad(exports, ["getDatasets","getDatasetsOutput"], () => require("./getDatasets"));


const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:DataLabellingService/dataset:Dataset":
                return new Dataset(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "DataLabellingService/dataset", _module)
