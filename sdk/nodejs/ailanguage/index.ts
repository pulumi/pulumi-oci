// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export { EndpointArgs, EndpointState } from "./endpoint";
export type Endpoint = import("./endpoint").Endpoint;
export const Endpoint: typeof import("./endpoint").Endpoint = null as any;
utilities.lazyLoad(exports, ["Endpoint"], () => require("./endpoint"));

export { GetEndpointArgs, GetEndpointResult, GetEndpointOutputArgs } from "./getEndpoint";
export const getEndpoint: typeof import("./getEndpoint").getEndpoint = null as any;
export const getEndpointOutput: typeof import("./getEndpoint").getEndpointOutput = null as any;
utilities.lazyLoad(exports, ["getEndpoint","getEndpointOutput"], () => require("./getEndpoint"));

export { GetEndpointsArgs, GetEndpointsResult, GetEndpointsOutputArgs } from "./getEndpoints";
export const getEndpoints: typeof import("./getEndpoints").getEndpoints = null as any;
export const getEndpointsOutput: typeof import("./getEndpoints").getEndpointsOutput = null as any;
utilities.lazyLoad(exports, ["getEndpoints","getEndpointsOutput"], () => require("./getEndpoints"));

export { GetModelArgs, GetModelResult, GetModelOutputArgs } from "./getModel";
export const getModel: typeof import("./getModel").getModel = null as any;
export const getModelOutput: typeof import("./getModel").getModelOutput = null as any;
utilities.lazyLoad(exports, ["getModel","getModelOutput"], () => require("./getModel"));

export { GetModelEvaluationResultsArgs, GetModelEvaluationResultsResult, GetModelEvaluationResultsOutputArgs } from "./getModelEvaluationResults";
export const getModelEvaluationResults: typeof import("./getModelEvaluationResults").getModelEvaluationResults = null as any;
export const getModelEvaluationResultsOutput: typeof import("./getModelEvaluationResults").getModelEvaluationResultsOutput = null as any;
utilities.lazyLoad(exports, ["getModelEvaluationResults","getModelEvaluationResultsOutput"], () => require("./getModelEvaluationResults"));

export { GetModelTypeArgs, GetModelTypeResult, GetModelTypeOutputArgs } from "./getModelType";
export const getModelType: typeof import("./getModelType").getModelType = null as any;
export const getModelTypeOutput: typeof import("./getModelType").getModelTypeOutput = null as any;
utilities.lazyLoad(exports, ["getModelType","getModelTypeOutput"], () => require("./getModelType"));

export { GetModelsArgs, GetModelsResult, GetModelsOutputArgs } from "./getModels";
export const getModels: typeof import("./getModels").getModels = null as any;
export const getModelsOutput: typeof import("./getModels").getModelsOutput = null as any;
utilities.lazyLoad(exports, ["getModels","getModelsOutput"], () => require("./getModels"));

export { GetProjectArgs, GetProjectResult, GetProjectOutputArgs } from "./getProject";
export const getProject: typeof import("./getProject").getProject = null as any;
export const getProjectOutput: typeof import("./getProject").getProjectOutput = null as any;
utilities.lazyLoad(exports, ["getProject","getProjectOutput"], () => require("./getProject"));

export { GetProjectsArgs, GetProjectsResult, GetProjectsOutputArgs } from "./getProjects";
export const getProjects: typeof import("./getProjects").getProjects = null as any;
export const getProjectsOutput: typeof import("./getProjects").getProjectsOutput = null as any;
utilities.lazyLoad(exports, ["getProjects","getProjectsOutput"], () => require("./getProjects"));

export { ModelArgs, ModelState } from "./model";
export type Model = import("./model").Model;
export const Model: typeof import("./model").Model = null as any;
utilities.lazyLoad(exports, ["Model"], () => require("./model"));

export { ProjectArgs, ProjectState } from "./project";
export type Project = import("./project").Project;
export const Project: typeof import("./project").Project = null as any;
utilities.lazyLoad(exports, ["Project"], () => require("./project"));


const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:AiLanguage/endpoint:Endpoint":
                return new Endpoint(name, <any>undefined, { urn })
            case "oci:AiLanguage/model:Model":
                return new Model(name, <any>undefined, { urn })
            case "oci:AiLanguage/project:Project":
                return new Project(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "AiLanguage/endpoint", _module)
pulumi.runtime.registerResourceModule("oci", "AiLanguage/model", _module)
pulumi.runtime.registerResourceModule("oci", "AiLanguage/project", _module)