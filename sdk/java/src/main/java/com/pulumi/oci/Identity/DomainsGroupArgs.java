// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Identity.inputs.DomainsGroupMemberArgs;
import com.pulumi.oci.Identity.inputs.DomainsGroupTagArgs;
import com.pulumi.oci.Identity.inputs.DomainsGroupUrnietfparamsscimschemasoracleidcsextensionOciTagsArgs;
import com.pulumi.oci.Identity.inputs.DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondynamicGroupArgs;
import com.pulumi.oci.Identity.inputs.DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupArgs;
import com.pulumi.oci.Identity.inputs.DomainsGroupUrnietfparamsscimschemasoracleidcsextensionposixGroupArgs;
import com.pulumi.oci.Identity.inputs.DomainsGroupUrnietfparamsscimschemasoracleidcsextensionrequestableGroupArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsGroupArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsGroupArgs Empty = new DomainsGroupArgs();

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
     * (Updatable) Group display name
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) Group display name
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service Provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value. The value of the externalId attribute is always issued by the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer&#39;s tenant.
     * 
     */
    @Import(name="externalId")
    private @Nullable Output<String> externalId;

    /**
     * @return (Updatable) An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service Provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value. The value of the externalId attribute is always issued by the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer&#39;s tenant.
     * 
     */
    public Optional<Output<String>> externalId() {
        return Optional.ofNullable(this.externalId);
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
     * (Updatable) Group members - when requesting members attribute, a max of 10,000 members will be returned in a single request. It is recommended to use startIndex and count to return members in pages instead of in a single response, eg : #attributes=members[startIndex=1%26count=10]
     * 
     */
    @Import(name="members")
    private @Nullable Output<List<DomainsGroupMemberArgs>> members;

    /**
     * @return (Updatable) Group members - when requesting members attribute, a max of 10,000 members will be returned in a single request. It is recommended to use startIndex and count to return members in pages instead of in a single response, eg : #attributes=members[startIndex=1%26count=10]
     * 
     */
    public Optional<Output<List<DomainsGroupMemberArgs>>> members() {
        return Optional.ofNullable(this.members);
    }

    /**
     * (Updatable) A human readable name for Group as defined by the Service Consumer
     * 
     */
    @Import(name="nonUniqueDisplayName")
    private @Nullable Output<String> nonUniqueDisplayName;

    /**
     * @return (Updatable) A human readable name for Group as defined by the Service Consumer
     * 
     */
    public Optional<Output<String>> nonUniqueDisplayName() {
        return Optional.ofNullable(this.nonUniqueDisplayName);
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
    private @Nullable Output<List<DomainsGroupTagArgs>> tags;

    /**
     * @return (Updatable) A list of tags on this resource.
     * 
     */
    public Optional<Output<List<DomainsGroupTagArgs>>> tags() {
        return Optional.ofNullable(this.tags);
    }

    /**
     * (Updatable) Oracle Cloud Infrastructure Tags.
     * 
     */
    @Import(name="urnietfparamsscimschemasoracleidcsextensionOciTags")
    private @Nullable Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensionOciTagsArgs> urnietfparamsscimschemasoracleidcsextensionOciTags;

    /**
     * @return (Updatable) Oracle Cloud Infrastructure Tags.
     * 
     */
    public Optional<Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensionOciTagsArgs>> urnietfparamsscimschemasoracleidcsextensionOciTags() {
        return Optional.ofNullable(this.urnietfparamsscimschemasoracleidcsextensionOciTags);
    }

    /**
     * (Updatable) Dynamic Group
     * 
     */
    @Import(name="urnietfparamsscimschemasoracleidcsextensiondynamicGroup")
    private @Nullable Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondynamicGroupArgs> urnietfparamsscimschemasoracleidcsextensiondynamicGroup;

    /**
     * @return (Updatable) Dynamic Group
     * 
     */
    public Optional<Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondynamicGroupArgs>> urnietfparamsscimschemasoracleidcsextensiondynamicGroup() {
        return Optional.ofNullable(this.urnietfparamsscimschemasoracleidcsextensiondynamicGroup);
    }

    /**
     * (Updatable) Idcs Group
     * 
     */
    @Import(name="urnietfparamsscimschemasoracleidcsextensiongroupGroup")
    private @Nullable Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupArgs> urnietfparamsscimschemasoracleidcsextensiongroupGroup;

    /**
     * @return (Updatable) Idcs Group
     * 
     */
    public Optional<Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupArgs>> urnietfparamsscimschemasoracleidcsextensiongroupGroup() {
        return Optional.ofNullable(this.urnietfparamsscimschemasoracleidcsextensiongroupGroup);
    }

    /**
     * (Updatable) POSIX Group extension
     * 
     */
    @Import(name="urnietfparamsscimschemasoracleidcsextensionposixGroup")
    private @Nullable Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensionposixGroupArgs> urnietfparamsscimschemasoracleidcsextensionposixGroup;

    /**
     * @return (Updatable) POSIX Group extension
     * 
     */
    public Optional<Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensionposixGroupArgs>> urnietfparamsscimschemasoracleidcsextensionposixGroup() {
        return Optional.ofNullable(this.urnietfparamsscimschemasoracleidcsextensionposixGroup);
    }

    /**
     * (Updatable) Requestable Group
     * 
     */
    @Import(name="urnietfparamsscimschemasoracleidcsextensionrequestableGroup")
    private @Nullable Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensionrequestableGroupArgs> urnietfparamsscimschemasoracleidcsextensionrequestableGroup;

    /**
     * @return (Updatable) Requestable Group
     * 
     */
    public Optional<Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensionrequestableGroupArgs>> urnietfparamsscimschemasoracleidcsextensionrequestableGroup() {
        return Optional.ofNullable(this.urnietfparamsscimschemasoracleidcsextensionrequestableGroup);
    }

    private DomainsGroupArgs() {}

    private DomainsGroupArgs(DomainsGroupArgs $) {
        this.attributeSets = $.attributeSets;
        this.attributes = $.attributes;
        this.authorization = $.authorization;
        this.displayName = $.displayName;
        this.externalId = $.externalId;
        this.idcsEndpoint = $.idcsEndpoint;
        this.members = $.members;
        this.nonUniqueDisplayName = $.nonUniqueDisplayName;
        this.ocid = $.ocid;
        this.resourceTypeSchemaVersion = $.resourceTypeSchemaVersion;
        this.schemas = $.schemas;
        this.tags = $.tags;
        this.urnietfparamsscimschemasoracleidcsextensionOciTags = $.urnietfparamsscimschemasoracleidcsextensionOciTags;
        this.urnietfparamsscimschemasoracleidcsextensiondynamicGroup = $.urnietfparamsscimschemasoracleidcsextensiondynamicGroup;
        this.urnietfparamsscimschemasoracleidcsextensiongroupGroup = $.urnietfparamsscimschemasoracleidcsextensiongroupGroup;
        this.urnietfparamsscimschemasoracleidcsextensionposixGroup = $.urnietfparamsscimschemasoracleidcsextensionposixGroup;
        this.urnietfparamsscimschemasoracleidcsextensionrequestableGroup = $.urnietfparamsscimschemasoracleidcsextensionrequestableGroup;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsGroupArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsGroupArgs $;

        public Builder() {
            $ = new DomainsGroupArgs();
        }

        public Builder(DomainsGroupArgs defaults) {
            $ = new DomainsGroupArgs(Objects.requireNonNull(defaults));
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
         * @param displayName (Updatable) Group display name
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Group display name
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param externalId (Updatable) An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service Provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value. The value of the externalId attribute is always issued by the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer&#39;s tenant.
         * 
         * @return builder
         * 
         */
        public Builder externalId(@Nullable Output<String> externalId) {
            $.externalId = externalId;
            return this;
        }

        /**
         * @param externalId (Updatable) An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service Provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value. The value of the externalId attribute is always issued by the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer&#39;s tenant.
         * 
         * @return builder
         * 
         */
        public Builder externalId(String externalId) {
            return externalId(Output.of(externalId));
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
         * @param members (Updatable) Group members - when requesting members attribute, a max of 10,000 members will be returned in a single request. It is recommended to use startIndex and count to return members in pages instead of in a single response, eg : #attributes=members[startIndex=1%26count=10]
         * 
         * @return builder
         * 
         */
        public Builder members(@Nullable Output<List<DomainsGroupMemberArgs>> members) {
            $.members = members;
            return this;
        }

        /**
         * @param members (Updatable) Group members - when requesting members attribute, a max of 10,000 members will be returned in a single request. It is recommended to use startIndex and count to return members in pages instead of in a single response, eg : #attributes=members[startIndex=1%26count=10]
         * 
         * @return builder
         * 
         */
        public Builder members(List<DomainsGroupMemberArgs> members) {
            return members(Output.of(members));
        }

        /**
         * @param members (Updatable) Group members - when requesting members attribute, a max of 10,000 members will be returned in a single request. It is recommended to use startIndex and count to return members in pages instead of in a single response, eg : #attributes=members[startIndex=1%26count=10]
         * 
         * @return builder
         * 
         */
        public Builder members(DomainsGroupMemberArgs... members) {
            return members(List.of(members));
        }

        /**
         * @param nonUniqueDisplayName (Updatable) A human readable name for Group as defined by the Service Consumer
         * 
         * @return builder
         * 
         */
        public Builder nonUniqueDisplayName(@Nullable Output<String> nonUniqueDisplayName) {
            $.nonUniqueDisplayName = nonUniqueDisplayName;
            return this;
        }

        /**
         * @param nonUniqueDisplayName (Updatable) A human readable name for Group as defined by the Service Consumer
         * 
         * @return builder
         * 
         */
        public Builder nonUniqueDisplayName(String nonUniqueDisplayName) {
            return nonUniqueDisplayName(Output.of(nonUniqueDisplayName));
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
        public Builder tags(@Nullable Output<List<DomainsGroupTagArgs>> tags) {
            $.tags = tags;
            return this;
        }

        /**
         * @param tags (Updatable) A list of tags on this resource.
         * 
         * @return builder
         * 
         */
        public Builder tags(List<DomainsGroupTagArgs> tags) {
            return tags(Output.of(tags));
        }

        /**
         * @param tags (Updatable) A list of tags on this resource.
         * 
         * @return builder
         * 
         */
        public Builder tags(DomainsGroupTagArgs... tags) {
            return tags(List.of(tags));
        }

        /**
         * @param urnietfparamsscimschemasoracleidcsextensionOciTags (Updatable) Oracle Cloud Infrastructure Tags.
         * 
         * @return builder
         * 
         */
        public Builder urnietfparamsscimschemasoracleidcsextensionOciTags(@Nullable Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensionOciTagsArgs> urnietfparamsscimschemasoracleidcsextensionOciTags) {
            $.urnietfparamsscimschemasoracleidcsextensionOciTags = urnietfparamsscimschemasoracleidcsextensionOciTags;
            return this;
        }

        /**
         * @param urnietfparamsscimschemasoracleidcsextensionOciTags (Updatable) Oracle Cloud Infrastructure Tags.
         * 
         * @return builder
         * 
         */
        public Builder urnietfparamsscimschemasoracleidcsextensionOciTags(DomainsGroupUrnietfparamsscimschemasoracleidcsextensionOciTagsArgs urnietfparamsscimschemasoracleidcsextensionOciTags) {
            return urnietfparamsscimschemasoracleidcsextensionOciTags(Output.of(urnietfparamsscimschemasoracleidcsextensionOciTags));
        }

        /**
         * @param urnietfparamsscimschemasoracleidcsextensiondynamicGroup (Updatable) Dynamic Group
         * 
         * @return builder
         * 
         */
        public Builder urnietfparamsscimschemasoracleidcsextensiondynamicGroup(@Nullable Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondynamicGroupArgs> urnietfparamsscimschemasoracleidcsextensiondynamicGroup) {
            $.urnietfparamsscimschemasoracleidcsextensiondynamicGroup = urnietfparamsscimschemasoracleidcsextensiondynamicGroup;
            return this;
        }

        /**
         * @param urnietfparamsscimschemasoracleidcsextensiondynamicGroup (Updatable) Dynamic Group
         * 
         * @return builder
         * 
         */
        public Builder urnietfparamsscimschemasoracleidcsextensiondynamicGroup(DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondynamicGroupArgs urnietfparamsscimschemasoracleidcsextensiondynamicGroup) {
            return urnietfparamsscimschemasoracleidcsextensiondynamicGroup(Output.of(urnietfparamsscimschemasoracleidcsextensiondynamicGroup));
        }

        /**
         * @param urnietfparamsscimschemasoracleidcsextensiongroupGroup (Updatable) Idcs Group
         * 
         * @return builder
         * 
         */
        public Builder urnietfparamsscimschemasoracleidcsextensiongroupGroup(@Nullable Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupArgs> urnietfparamsscimschemasoracleidcsextensiongroupGroup) {
            $.urnietfparamsscimschemasoracleidcsextensiongroupGroup = urnietfparamsscimschemasoracleidcsextensiongroupGroup;
            return this;
        }

        /**
         * @param urnietfparamsscimschemasoracleidcsextensiongroupGroup (Updatable) Idcs Group
         * 
         * @return builder
         * 
         */
        public Builder urnietfparamsscimschemasoracleidcsextensiongroupGroup(DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupArgs urnietfparamsscimschemasoracleidcsextensiongroupGroup) {
            return urnietfparamsscimschemasoracleidcsextensiongroupGroup(Output.of(urnietfparamsscimschemasoracleidcsextensiongroupGroup));
        }

        /**
         * @param urnietfparamsscimschemasoracleidcsextensionposixGroup (Updatable) POSIX Group extension
         * 
         * @return builder
         * 
         */
        public Builder urnietfparamsscimschemasoracleidcsextensionposixGroup(@Nullable Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensionposixGroupArgs> urnietfparamsscimschemasoracleidcsextensionposixGroup) {
            $.urnietfparamsscimschemasoracleidcsextensionposixGroup = urnietfparamsscimschemasoracleidcsextensionposixGroup;
            return this;
        }

        /**
         * @param urnietfparamsscimschemasoracleidcsextensionposixGroup (Updatable) POSIX Group extension
         * 
         * @return builder
         * 
         */
        public Builder urnietfparamsscimschemasoracleidcsextensionposixGroup(DomainsGroupUrnietfparamsscimschemasoracleidcsextensionposixGroupArgs urnietfparamsscimschemasoracleidcsextensionposixGroup) {
            return urnietfparamsscimschemasoracleidcsextensionposixGroup(Output.of(urnietfparamsscimschemasoracleidcsextensionposixGroup));
        }

        /**
         * @param urnietfparamsscimschemasoracleidcsextensionrequestableGroup (Updatable) Requestable Group
         * 
         * @return builder
         * 
         */
        public Builder urnietfparamsscimschemasoracleidcsextensionrequestableGroup(@Nullable Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensionrequestableGroupArgs> urnietfparamsscimschemasoracleidcsextensionrequestableGroup) {
            $.urnietfparamsscimschemasoracleidcsextensionrequestableGroup = urnietfparamsscimschemasoracleidcsextensionrequestableGroup;
            return this;
        }

        /**
         * @param urnietfparamsscimschemasoracleidcsextensionrequestableGroup (Updatable) Requestable Group
         * 
         * @return builder
         * 
         */
        public Builder urnietfparamsscimschemasoracleidcsextensionrequestableGroup(DomainsGroupUrnietfparamsscimschemasoracleidcsextensionrequestableGroupArgs urnietfparamsscimschemasoracleidcsextensionrequestableGroup) {
            return urnietfparamsscimschemasoracleidcsextensionrequestableGroup(Output.of(urnietfparamsscimschemasoracleidcsextensionrequestableGroup));
        }

        public DomainsGroupArgs build() {
            $.displayName = Objects.requireNonNull($.displayName, "expected parameter 'displayName' to be non-null");
            $.idcsEndpoint = Objects.requireNonNull($.idcsEndpoint, "expected parameter 'idcsEndpoint' to be non-null");
            $.schemas = Objects.requireNonNull($.schemas, "expected parameter 'schemas' to be non-null");
            return $;
        }
    }

}