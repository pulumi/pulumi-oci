// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Identity.inputs.DomainsDynamicResourceGroupTagArgs;
import com.pulumi.oci.Identity.inputs.DomainsDynamicResourceGroupUrnietfparamsscimschemasoracleidcsextensionOciTagsArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsDynamicResourceGroupArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsDynamicResourceGroupArgs Empty = new DomainsDynamicResourceGroupArgs();

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
     * (Updatable) text that explains the purpose of this Dynamic Resource Group
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) text that explains the purpose of this Dynamic Resource Group
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) User-friendly, mutable identifier
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) User-friendly, mutable identifier
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
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
     * (Updatable) Store as a string the matching-rule for this Dynamic Resource Group. This may match any number of Apps in this Domain, as well as matching any number of Oracle Cloud Infrastructure resources that are not in any Domain but that are in the Oracle Cloud Infrastructure Compartment that contains this Domain.
     * 
     */
    @Import(name="matchingRule", required=true)
    private Output<String> matchingRule;

    /**
     * @return (Updatable) Store as a string the matching-rule for this Dynamic Resource Group. This may match any number of Apps in this Domain, as well as matching any number of Oracle Cloud Infrastructure resources that are not in any Domain but that are in the Oracle Cloud Infrastructure Compartment that contains this Domain.
     * 
     */
    public Output<String> matchingRule() {
        return this.matchingRule;
    }

    /**
     * (Updatable) Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     * 
     */
    @Import(name="ocid")
    private @Nullable Output<String> ocid;

    /**
     * @return (Updatable) Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
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
     */
    @Import(name="schemas", required=true)
    private Output<List<String>> schemas;

    /**
     * @return (Updatable) REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     * 
     */
    public Output<List<String>> schemas() {
        return this.schemas;
    }

    /**
     * (Updatable) A list of tags on this resource.
     * 
     */
    @Import(name="tags")
    private @Nullable Output<List<DomainsDynamicResourceGroupTagArgs>> tags;

    /**
     * @return (Updatable) A list of tags on this resource.
     * 
     */
    public Optional<Output<List<DomainsDynamicResourceGroupTagArgs>>> tags() {
        return Optional.ofNullable(this.tags);
    }

    /**
     * (Updatable) Oracle Cloud Infrastructure Tags.
     * 
     */
    @Import(name="urnietfparamsscimschemasoracleidcsextensionOciTags")
    private @Nullable Output<DomainsDynamicResourceGroupUrnietfparamsscimschemasoracleidcsextensionOciTagsArgs> urnietfparamsscimschemasoracleidcsextensionOciTags;

    /**
     * @return (Updatable) Oracle Cloud Infrastructure Tags.
     * 
     */
    public Optional<Output<DomainsDynamicResourceGroupUrnietfparamsscimschemasoracleidcsextensionOciTagsArgs>> urnietfparamsscimschemasoracleidcsextensionOciTags() {
        return Optional.ofNullable(this.urnietfparamsscimschemasoracleidcsextensionOciTags);
    }

    private DomainsDynamicResourceGroupArgs() {}

    private DomainsDynamicResourceGroupArgs(DomainsDynamicResourceGroupArgs $) {
        this.attributeSets = $.attributeSets;
        this.attributes = $.attributes;
        this.authorization = $.authorization;
        this.description = $.description;
        this.displayName = $.displayName;
        this.idcsEndpoint = $.idcsEndpoint;
        this.matchingRule = $.matchingRule;
        this.ocid = $.ocid;
        this.resourceTypeSchemaVersion = $.resourceTypeSchemaVersion;
        this.schemas = $.schemas;
        this.tags = $.tags;
        this.urnietfparamsscimschemasoracleidcsextensionOciTags = $.urnietfparamsscimschemasoracleidcsextensionOciTags;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsDynamicResourceGroupArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsDynamicResourceGroupArgs $;

        public Builder() {
            $ = new DomainsDynamicResourceGroupArgs();
        }

        public Builder(DomainsDynamicResourceGroupArgs defaults) {
            $ = new DomainsDynamicResourceGroupArgs(Objects.requireNonNull(defaults));
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
         * @param description (Updatable) text that explains the purpose of this Dynamic Resource Group
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) text that explains the purpose of this Dynamic Resource Group
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) User-friendly, mutable identifier
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) User-friendly, mutable identifier
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
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
         * @param matchingRule (Updatable) Store as a string the matching-rule for this Dynamic Resource Group. This may match any number of Apps in this Domain, as well as matching any number of Oracle Cloud Infrastructure resources that are not in any Domain but that are in the Oracle Cloud Infrastructure Compartment that contains this Domain.
         * 
         * @return builder
         * 
         */
        public Builder matchingRule(Output<String> matchingRule) {
            $.matchingRule = matchingRule;
            return this;
        }

        /**
         * @param matchingRule (Updatable) Store as a string the matching-rule for this Dynamic Resource Group. This may match any number of Apps in this Domain, as well as matching any number of Oracle Cloud Infrastructure resources that are not in any Domain but that are in the Oracle Cloud Infrastructure Compartment that contains this Domain.
         * 
         * @return builder
         * 
         */
        public Builder matchingRule(String matchingRule) {
            return matchingRule(Output.of(matchingRule));
        }

        /**
         * @param ocid (Updatable) Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
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
         * @return builder
         * 
         */
        public Builder schemas(List<String> schemas) {
            return schemas(Output.of(schemas));
        }

        /**
         * @param schemas (Updatable) REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
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
         * @return builder
         * 
         */
        public Builder tags(@Nullable Output<List<DomainsDynamicResourceGroupTagArgs>> tags) {
            $.tags = tags;
            return this;
        }

        /**
         * @param tags (Updatable) A list of tags on this resource.
         * 
         * @return builder
         * 
         */
        public Builder tags(List<DomainsDynamicResourceGroupTagArgs> tags) {
            return tags(Output.of(tags));
        }

        /**
         * @param tags (Updatable) A list of tags on this resource.
         * 
         * @return builder
         * 
         */
        public Builder tags(DomainsDynamicResourceGroupTagArgs... tags) {
            return tags(List.of(tags));
        }

        /**
         * @param urnietfparamsscimschemasoracleidcsextensionOciTags (Updatable) Oracle Cloud Infrastructure Tags.
         * 
         * @return builder
         * 
         */
        public Builder urnietfparamsscimschemasoracleidcsextensionOciTags(@Nullable Output<DomainsDynamicResourceGroupUrnietfparamsscimschemasoracleidcsextensionOciTagsArgs> urnietfparamsscimschemasoracleidcsextensionOciTags) {
            $.urnietfparamsscimschemasoracleidcsextensionOciTags = urnietfparamsscimschemasoracleidcsextensionOciTags;
            return this;
        }

        /**
         * @param urnietfparamsscimschemasoracleidcsextensionOciTags (Updatable) Oracle Cloud Infrastructure Tags.
         * 
         * @return builder
         * 
         */
        public Builder urnietfparamsscimschemasoracleidcsextensionOciTags(DomainsDynamicResourceGroupUrnietfparamsscimschemasoracleidcsextensionOciTagsArgs urnietfparamsscimschemasoracleidcsextensionOciTags) {
            return urnietfparamsscimschemasoracleidcsextensionOciTags(Output.of(urnietfparamsscimschemasoracleidcsextensionOciTags));
        }

        public DomainsDynamicResourceGroupArgs build() {
            $.displayName = Objects.requireNonNull($.displayName, "expected parameter 'displayName' to be non-null");
            $.idcsEndpoint = Objects.requireNonNull($.idcsEndpoint, "expected parameter 'idcsEndpoint' to be non-null");
            $.matchingRule = Objects.requireNonNull($.matchingRule, "expected parameter 'matchingRule' to be non-null");
            $.schemas = Objects.requireNonNull($.schemas, "expected parameter 'schemas' to be non-null");
            return $;
        }
    }

}