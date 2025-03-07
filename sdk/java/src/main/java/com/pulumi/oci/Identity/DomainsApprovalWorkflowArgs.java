// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.inputs.DomainsApprovalWorkflowApprovalWorkflowStepArgs;
import com.pulumi.oci.Identity.inputs.DomainsApprovalWorkflowMaxDurationArgs;
import com.pulumi.oci.Identity.inputs.DomainsApprovalWorkflowTagArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsApprovalWorkflowArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsApprovalWorkflowArgs Empty = new DomainsApprovalWorkflowArgs();

    /**
     * (Updatable) ApprovalWorkflowSteps applicable for the ApprovalWorkflowInstance.
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * idcsCompositeKey: [value, type]
     * * multiValued: true
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: complex
     * * uniqueness: none
     * 
     */
    @Import(name="approvalWorkflowSteps")
    private @Nullable Output<List<DomainsApprovalWorkflowApprovalWorkflowStepArgs>> approvalWorkflowSteps;

    /**
     * @return (Updatable) ApprovalWorkflowSteps applicable for the ApprovalWorkflowInstance.
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * idcsCompositeKey: [value, type]
     * * multiValued: true
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: complex
     * * uniqueness: none
     * 
     */
    public Optional<Output<List<DomainsApprovalWorkflowApprovalWorkflowStepArgs>>> approvalWorkflowSteps() {
        return Optional.ofNullable(this.approvalWorkflowSteps);
    }

    /**
     * (Updatable) A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If &#39;attributes&#39; query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
     * 
     */
    @Import(name="attributeSets")
    private @Nullable Output<List<String>> attributeSets;

    /**
     * @return (Updatable) A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If &#39;attributes&#39; query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
     * 
     */
    public Optional<Output<List<String>>> attributeSets() {
        return Optional.ofNullable(this.attributeSets);
    }

    /**
     * (Updatable) A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
     * 
     */
    @Import(name="attributes")
    private @Nullable Output<String> attributes;

    /**
     * @return (Updatable) A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
     * 
     */
    public Optional<Output<String>> attributes() {
        return Optional.ofNullable(this.attributes);
    }

    /**
     * (Updatable) The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     * 
     */
    @Import(name="authorization")
    private @Nullable Output<String> authorization;

    /**
     * @return (Updatable) The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     * 
     */
    public Optional<Output<String>> authorization() {
        return Optional.ofNullable(this.authorization);
    }

    /**
     * (Updatable) Description of the ApprovalWorkflow.
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) Description of the ApprovalWorkflow.
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * The basic endpoint for the identity domain
     * 
     */
    @Import(name="idcsEndpoint", required=true)
    private Output<String> idcsEndpoint;

    /**
     * @return The basic endpoint for the identity domain
     * 
     */
    public Output<String> idcsEndpoint() {
        return this.idcsEndpoint;
    }

    /**
     * (Updatable) Max duration of the ApprovalWorkflow must be acted at all levels.
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: true
     * * returned: default
     * * type: complex
     * * uniqueness: none
     * 
     */
    @Import(name="maxDuration", required=true)
    private Output<DomainsApprovalWorkflowMaxDurationArgs> maxDuration;

    /**
     * @return (Updatable) Max duration of the ApprovalWorkflow must be acted at all levels.
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: true
     * * returned: default
     * * type: complex
     * * uniqueness: none
     * 
     */
    public Output<DomainsApprovalWorkflowMaxDurationArgs> maxDuration() {
        return this.maxDuration;
    }

    /**
     * (Updatable) Name of the ApprovalWorkflow.
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: server
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return (Updatable) Name of the ApprovalWorkflow.
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: server
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: global
     * 
     */
    @Import(name="ocid")
    private @Nullable Output<String> ocid;

    /**
     * @return (Updatable) Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: global
     * 
     */
    public Optional<Output<String>> ocid() {
        return Optional.ofNullable(this.ocid);
    }

    /**
     * (Updatable) An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     * 
     */
    @Import(name="resourceTypeSchemaVersion")
    private @Nullable Output<String> resourceTypeSchemaVersion;

    /**
     * @return (Updatable) An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     * 
     */
    public Optional<Output<String>> resourceTypeSchemaVersion() {
        return Optional.ofNullable(this.resourceTypeSchemaVersion);
    }

    /**
     * (Updatable) REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: true
     * * mutability: readWrite
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="schemas", required=true)
    private Output<List<String>> schemas;

    /**
     * @return (Updatable) REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: true
     * * mutability: readWrite
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Output<List<String>> schemas() {
        return this.schemas;
    }

    /**
     * (Updatable) A list of tags on this resource.
     * 
     * **SCIM++ Properties:**
     * * idcsCompositeKey: [key, value]
     * * idcsSearchable: true
     * * multiValued: true
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: complex
     * * uniqueness: none
     * 
     */
    @Import(name="tags")
    private @Nullable Output<List<DomainsApprovalWorkflowTagArgs>> tags;

    /**
     * @return (Updatable) A list of tags on this resource.
     * 
     * **SCIM++ Properties:**
     * * idcsCompositeKey: [key, value]
     * * idcsSearchable: true
     * * multiValued: true
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * type: complex
     * * uniqueness: none
     * 
     */
    public Optional<Output<List<DomainsApprovalWorkflowTagArgs>>> tags() {
        return Optional.ofNullable(this.tags);
    }

    private DomainsApprovalWorkflowArgs() {}

    private DomainsApprovalWorkflowArgs(DomainsApprovalWorkflowArgs $) {
        this.approvalWorkflowSteps = $.approvalWorkflowSteps;
        this.attributeSets = $.attributeSets;
        this.attributes = $.attributes;
        this.authorization = $.authorization;
        this.description = $.description;
        this.idcsEndpoint = $.idcsEndpoint;
        this.maxDuration = $.maxDuration;
        this.name = $.name;
        this.ocid = $.ocid;
        this.resourceTypeSchemaVersion = $.resourceTypeSchemaVersion;
        this.schemas = $.schemas;
        this.tags = $.tags;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsApprovalWorkflowArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsApprovalWorkflowArgs $;

        public Builder() {
            $ = new DomainsApprovalWorkflowArgs();
        }

        public Builder(DomainsApprovalWorkflowArgs defaults) {
            $ = new DomainsApprovalWorkflowArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param approvalWorkflowSteps (Updatable) ApprovalWorkflowSteps applicable for the ApprovalWorkflowInstance.
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * idcsCompositeKey: [value, type]
         * * multiValued: true
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: complex
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder approvalWorkflowSteps(@Nullable Output<List<DomainsApprovalWorkflowApprovalWorkflowStepArgs>> approvalWorkflowSteps) {
            $.approvalWorkflowSteps = approvalWorkflowSteps;
            return this;
        }

        /**
         * @param approvalWorkflowSteps (Updatable) ApprovalWorkflowSteps applicable for the ApprovalWorkflowInstance.
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * idcsCompositeKey: [value, type]
         * * multiValued: true
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: complex
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder approvalWorkflowSteps(List<DomainsApprovalWorkflowApprovalWorkflowStepArgs> approvalWorkflowSteps) {
            return approvalWorkflowSteps(Output.of(approvalWorkflowSteps));
        }

        /**
         * @param approvalWorkflowSteps (Updatable) ApprovalWorkflowSteps applicable for the ApprovalWorkflowInstance.
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * idcsCompositeKey: [value, type]
         * * multiValued: true
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: complex
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder approvalWorkflowSteps(DomainsApprovalWorkflowApprovalWorkflowStepArgs... approvalWorkflowSteps) {
            return approvalWorkflowSteps(List.of(approvalWorkflowSteps));
        }

        /**
         * @param attributeSets (Updatable) A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If &#39;attributes&#39; query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder attributeSets(@Nullable Output<List<String>> attributeSets) {
            $.attributeSets = attributeSets;
            return this;
        }

        /**
         * @param attributeSets (Updatable) A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If &#39;attributes&#39; query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder attributeSets(List<String> attributeSets) {
            return attributeSets(Output.of(attributeSets));
        }

        /**
         * @param attributeSets (Updatable) A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If &#39;attributes&#39; query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder attributeSets(String... attributeSets) {
            return attributeSets(List.of(attributeSets));
        }

        /**
         * @param attributes (Updatable) A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
         * 
         * @return builder
         * 
         */
        public Builder attributes(@Nullable Output<String> attributes) {
            $.attributes = attributes;
            return this;
        }

        /**
         * @param attributes (Updatable) A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
         * 
         * @return builder
         * 
         */
        public Builder attributes(String attributes) {
            return attributes(Output.of(attributes));
        }

        /**
         * @param authorization (Updatable) The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
         * 
         * @return builder
         * 
         */
        public Builder authorization(@Nullable Output<String> authorization) {
            $.authorization = authorization;
            return this;
        }

        /**
         * @param authorization (Updatable) The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
         * 
         * @return builder
         * 
         */
        public Builder authorization(String authorization) {
            return authorization(Output.of(authorization));
        }

        /**
         * @param description (Updatable) Description of the ApprovalWorkflow.
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) Description of the ApprovalWorkflow.
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param idcsEndpoint The basic endpoint for the identity domain
         * 
         * @return builder
         * 
         */
        public Builder idcsEndpoint(Output<String> idcsEndpoint) {
            $.idcsEndpoint = idcsEndpoint;
            return this;
        }

        /**
         * @param idcsEndpoint The basic endpoint for the identity domain
         * 
         * @return builder
         * 
         */
        public Builder idcsEndpoint(String idcsEndpoint) {
            return idcsEndpoint(Output.of(idcsEndpoint));
        }

        /**
         * @param maxDuration (Updatable) Max duration of the ApprovalWorkflow must be acted at all levels.
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readWrite
         * * required: true
         * * returned: default
         * * type: complex
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder maxDuration(Output<DomainsApprovalWorkflowMaxDurationArgs> maxDuration) {
            $.maxDuration = maxDuration;
            return this;
        }

        /**
         * @param maxDuration (Updatable) Max duration of the ApprovalWorkflow must be acted at all levels.
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readWrite
         * * required: true
         * * returned: default
         * * type: complex
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder maxDuration(DomainsApprovalWorkflowMaxDurationArgs maxDuration) {
            return maxDuration(Output.of(maxDuration));
        }

        /**
         * @param name (Updatable) Name of the ApprovalWorkflow.
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: immutable
         * * required: true
         * * returned: default
         * * type: string
         * * uniqueness: server
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) Name of the ApprovalWorkflow.
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: immutable
         * * required: true
         * * returned: default
         * * type: string
         * * uniqueness: server
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param ocid (Updatable) Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: immutable
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: global
         * 
         * @return builder
         * 
         */
        public Builder ocid(@Nullable Output<String> ocid) {
            $.ocid = ocid;
            return this;
        }

        /**
         * @param ocid (Updatable) Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: immutable
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: global
         * 
         * @return builder
         * 
         */
        public Builder ocid(String ocid) {
            return ocid(Output.of(ocid));
        }

        /**
         * @param resourceTypeSchemaVersion (Updatable) An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
         * 
         * @return builder
         * 
         */
        public Builder resourceTypeSchemaVersion(@Nullable Output<String> resourceTypeSchemaVersion) {
            $.resourceTypeSchemaVersion = resourceTypeSchemaVersion;
            return this;
        }

        /**
         * @param resourceTypeSchemaVersion (Updatable) An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
         * 
         * @return builder
         * 
         */
        public Builder resourceTypeSchemaVersion(String resourceTypeSchemaVersion) {
            return resourceTypeSchemaVersion(Output.of(resourceTypeSchemaVersion));
        }

        /**
         * @param schemas (Updatable) REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: false
         * * multiValued: true
         * * mutability: readWrite
         * * required: true
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder schemas(Output<List<String>> schemas) {
            $.schemas = schemas;
            return this;
        }

        /**
         * @param schemas (Updatable) REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: false
         * * multiValued: true
         * * mutability: readWrite
         * * required: true
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder schemas(List<String> schemas) {
            return schemas(Output.of(schemas));
        }

        /**
         * @param schemas (Updatable) REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: false
         * * multiValued: true
         * * mutability: readWrite
         * * required: true
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder schemas(String... schemas) {
            return schemas(List.of(schemas));
        }

        /**
         * @param tags (Updatable) A list of tags on this resource.
         * 
         * **SCIM++ Properties:**
         * * idcsCompositeKey: [key, value]
         * * idcsSearchable: true
         * * multiValued: true
         * * mutability: readWrite
         * * required: false
         * * returned: request
         * * type: complex
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder tags(@Nullable Output<List<DomainsApprovalWorkflowTagArgs>> tags) {
            $.tags = tags;
            return this;
        }

        /**
         * @param tags (Updatable) A list of tags on this resource.
         * 
         * **SCIM++ Properties:**
         * * idcsCompositeKey: [key, value]
         * * idcsSearchable: true
         * * multiValued: true
         * * mutability: readWrite
         * * required: false
         * * returned: request
         * * type: complex
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder tags(List<DomainsApprovalWorkflowTagArgs> tags) {
            return tags(Output.of(tags));
        }

        /**
         * @param tags (Updatable) A list of tags on this resource.
         * 
         * **SCIM++ Properties:**
         * * idcsCompositeKey: [key, value]
         * * idcsSearchable: true
         * * multiValued: true
         * * mutability: readWrite
         * * required: false
         * * returned: request
         * * type: complex
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder tags(DomainsApprovalWorkflowTagArgs... tags) {
            return tags(List.of(tags));
        }

        public DomainsApprovalWorkflowArgs build() {
            if ($.idcsEndpoint == null) {
                throw new MissingRequiredPropertyException("DomainsApprovalWorkflowArgs", "idcsEndpoint");
            }
            if ($.maxDuration == null) {
                throw new MissingRequiredPropertyException("DomainsApprovalWorkflowArgs", "maxDuration");
            }
            if ($.schemas == null) {
                throw new MissingRequiredPropertyException("DomainsApprovalWorkflowArgs", "schemas");
            }
            return $;
        }
    }

}
