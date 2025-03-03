// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Identity.DomainsGroupArgs;
import com.pulumi.oci.Identity.inputs.DomainsGroupState;
import com.pulumi.oci.Identity.outputs.DomainsGroupIdcsCreatedBy;
import com.pulumi.oci.Identity.outputs.DomainsGroupIdcsLastModifiedBy;
import com.pulumi.oci.Identity.outputs.DomainsGroupMember;
import com.pulumi.oci.Identity.outputs.DomainsGroupMeta;
import com.pulumi.oci.Identity.outputs.DomainsGroupTag;
import com.pulumi.oci.Identity.outputs.DomainsGroupUrnietfparamsscimschemasoracleidcsextensionOciTags;
import com.pulumi.oci.Identity.outputs.DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroup;
import com.pulumi.oci.Identity.outputs.DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondynamicGroup;
import com.pulumi.oci.Identity.outputs.DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroup;
import com.pulumi.oci.Identity.outputs.DomainsGroupUrnietfparamsscimschemasoracleidcsextensionposixGroup;
import com.pulumi.oci.Identity.outputs.DomainsGroupUrnietfparamsscimschemasoracleidcsextensionrequestableGroup;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Group resource in Oracle Cloud Infrastructure Identity Domains service.
 * 
 * Create a group.
 * 
 * ## Example Usage
 * 
 * &lt;!--Start PulumiCodeChooser --&gt;
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 * ## Import
 * 
 * Groups can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:Identity/domainsGroup:DomainsGroup test_group &#34;idcsEndpoint/{idcsEndpoint}/groups/{groupId}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Identity/domainsGroup:DomainsGroup")
public class DomainsGroup extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If &#39;attributes&#39; query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
     * 
     */
    @Export(name="attributeSets", refs={List.class,String.class}, tree="[0,1]")
    private Output</* @Nullable */ List<String>> attributeSets;

    /**
     * @return (Updatable) A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If &#39;attributes&#39; query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
     * 
     */
    public Output<Optional<List<String>>> attributeSets() {
        return Codegen.optional(this.attributeSets);
    }
    /**
     * (Updatable) A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
     * 
     */
    @Export(name="attributes", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> attributes;

    /**
     * @return (Updatable) A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
     * 
     */
    public Output<Optional<String>> attributes() {
        return Codegen.optional(this.attributes);
    }
    /**
     * (Updatable) The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     * 
     */
    @Export(name="authorization", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> authorization;

    /**
     * @return (Updatable) The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     * 
     */
    public Output<Optional<String>> authorization() {
        return Codegen.optional(this.authorization);
    }
    /**
     * (Updatable) Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Export(name="compartmentOcid", refs={String.class}, tree="[0]")
    private Output<String> compartmentOcid;

    /**
     * @return (Updatable) Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Output<String> compartmentOcid() {
        return this.compartmentOcid;
    }
    /**
     * (Updatable) A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    @Export(name="deleteInProgress", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> deleteInProgress;

    /**
     * @return (Updatable) A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    public Output<Boolean> deleteInProgress() {
        return this.deleteInProgress;
    }
    /**
     * (Updatable) The Group display name.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsCsvAttributeName: Display Name
     * * idcsCsvAttributeNameMappings: [[columnHeaderName:Name, deprecatedColumnHeaderName:Display Name]]
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: true
     * * returned: always
     * * type: string
     * * uniqueness: global
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) The Group display name.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsCsvAttributeName: Display Name
     * * idcsCsvAttributeNameMappings: [[columnHeaderName:Name, deprecatedColumnHeaderName:Display Name]]
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: true
     * * returned: always
     * * type: string
     * * uniqueness: global
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Export(name="domainOcid", refs={String.class}, tree="[0]")
    private Output<String> domainOcid;

    /**
     * @return (Updatable) Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Output<String> domainOcid() {
        return this.domainOcid;
    }
    /**
     * (Updatable) An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service Provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value. The value of the externalId attribute is always issued by the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer&#39;s tenant.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Export(name="externalId", refs={String.class}, tree="[0]")
    private Output<String> externalId;

    /**
     * @return (Updatable) An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service Provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value. The value of the externalId attribute is always issued by the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer&#39;s tenant.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Output<String> externalId() {
        return this.externalId;
    }
    @Export(name="forceDelete", refs={Boolean.class}, tree="[0]")
    private Output</* @Nullable */ Boolean> forceDelete;

    public Output<Optional<Boolean>> forceDelete() {
        return Codegen.optional(this.forceDelete);
    }
    /**
     * (Updatable) The User or App who created the Resource
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: true
     * * returned: default
     * * type: complex
     * 
     */
    @Export(name="idcsCreatedBies", refs={List.class,DomainsGroupIdcsCreatedBy.class}, tree="[0,1]")
    private Output<List<DomainsGroupIdcsCreatedBy>> idcsCreatedBies;

    /**
     * @return (Updatable) The User or App who created the Resource
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: true
     * * returned: default
     * * type: complex
     * 
     */
    public Output<List<DomainsGroupIdcsCreatedBy>> idcsCreatedBies() {
        return this.idcsCreatedBies;
    }
    /**
     * The basic endpoint for the identity domain
     * 
     */
    @Export(name="idcsEndpoint", refs={String.class}, tree="[0]")
    private Output<String> idcsEndpoint;

    /**
     * @return The basic endpoint for the identity domain
     * 
     */
    public Output<String> idcsEndpoint() {
        return this.idcsEndpoint;
    }
    /**
     * (Updatable) The User or App who modified the Resource
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: complex
     * 
     */
    @Export(name="idcsLastModifiedBies", refs={List.class,DomainsGroupIdcsLastModifiedBy.class}, tree="[0,1]")
    private Output<List<DomainsGroupIdcsLastModifiedBy>> idcsLastModifiedBies;

    /**
     * @return (Updatable) The User or App who modified the Resource
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: complex
     * 
     */
    public Output<List<DomainsGroupIdcsLastModifiedBy>> idcsLastModifiedBies() {
        return this.idcsLastModifiedBies;
    }
    /**
     * (Updatable) The release number when the resource was upgraded.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    @Export(name="idcsLastUpgradedInRelease", refs={String.class}, tree="[0]")
    private Output<String> idcsLastUpgradedInRelease;

    /**
     * @return (Updatable) The release number when the resource was upgraded.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    public Output<String> idcsLastUpgradedInRelease() {
        return this.idcsLastUpgradedInRelease;
    }
    /**
     * (Updatable) Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: true
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    @Export(name="idcsPreventedOperations", refs={List.class,String.class}, tree="[0,1]")
    private Output<List<String>> idcsPreventedOperations;

    /**
     * @return (Updatable) Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: true
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * type: string
     * * uniqueness: none
     * 
     */
    public Output<List<String>> idcsPreventedOperations() {
        return this.idcsPreventedOperations;
    }
    /**
     * (Updatable) The group members. &lt;b&gt;Important:&lt;/b&gt; When requesting group members, a maximum of 10,000 members can be returned in a single request. If the response contains more than 10,000 members, the request will fail. Use &#39;startIndex&#39; and &#39;count&#39; to return members in pages instead of in a single response, for example: #attributes=members[startIndex=1%26count=10]. This REST API is SCIM compliant.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsCompositeKey: [value]
     * * idcsCsvAttributeNameMappings: [[columnHeaderName:User Members, mapsTo:members[User].value, multiValueDelimiter:;]]
     * * idcsSearchable: true
     * * multiValued: true
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * idcsPaginateResponse: true
     * * type: complex
     * * uniqueness: none
     * 
     */
    @Export(name="members", refs={List.class,DomainsGroupMember.class}, tree="[0,1]")
    private Output<List<DomainsGroupMember>> members;

    /**
     * @return (Updatable) The group members. &lt;b&gt;Important:&lt;/b&gt; When requesting group members, a maximum of 10,000 members can be returned in a single request. If the response contains more than 10,000 members, the request will fail. Use &#39;startIndex&#39; and &#39;count&#39; to return members in pages instead of in a single response, for example: #attributes=members[startIndex=1%26count=10]. This REST API is SCIM compliant.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsCompositeKey: [value]
     * * idcsCsvAttributeNameMappings: [[columnHeaderName:User Members, mapsTo:members[User].value, multiValueDelimiter:;]]
     * * idcsSearchable: true
     * * multiValued: true
     * * mutability: readWrite
     * * required: false
     * * returned: request
     * * idcsPaginateResponse: true
     * * type: complex
     * * uniqueness: none
     * 
     */
    public Output<List<DomainsGroupMember>> members() {
        return this.members;
    }
    /**
     * (Updatable) A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * idcsCsvAttributeNameMappings: [[columnHeaderName:Created Date, mapsTo:meta.created]]
     * * type: complex
     * 
     */
    @Export(name="metas", refs={List.class,DomainsGroupMeta.class}, tree="[0,1]")
    private Output<List<DomainsGroupMeta>> metas;

    /**
     * @return (Updatable) A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * idcsCsvAttributeNameMappings: [[columnHeaderName:Created Date, mapsTo:meta.created]]
     * * type: complex
     * 
     */
    public Output<List<DomainsGroupMeta>> metas() {
        return this.metas;
    }
    /**
     * (Updatable) A human readable name for the group as defined by the Service Consumer.
     * 
     * **Added In:** 2011192329
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsCsvAttributeName: Non-Unique Display Name
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: always
     * * type: string
     * 
     */
    @Export(name="nonUniqueDisplayName", refs={String.class}, tree="[0]")
    private Output<String> nonUniqueDisplayName;

    /**
     * @return (Updatable) A human readable name for the group as defined by the Service Consumer.
     * 
     * **Added In:** 2011192329
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsCsvAttributeName: Non-Unique Display Name
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: always
     * * type: string
     * 
     */
    public Output<String> nonUniqueDisplayName() {
        return this.nonUniqueDisplayName;
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
    @Export(name="ocid", refs={String.class}, tree="[0]")
    private Output<String> ocid;

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
    public Output<String> ocid() {
        return this.ocid;
    }
    /**
     * (Updatable) An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     * 
     */
    @Export(name="resourceTypeSchemaVersion", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> resourceTypeSchemaVersion;

    /**
     * @return (Updatable) An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     * 
     */
    public Output<Optional<String>> resourceTypeSchemaVersion() {
        return Codegen.optional(this.resourceTypeSchemaVersion);
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
    @Export(name="schemas", refs={List.class,String.class}, tree="[0,1]")
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
    @Export(name="tags", refs={List.class,DomainsGroupTag.class}, tree="[0,1]")
    private Output<List<DomainsGroupTag>> tags;

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
    public Output<List<DomainsGroupTag>> tags() {
        return this.tags;
    }
    /**
     * (Updatable) Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Export(name="tenancyOcid", refs={String.class}, tree="[0]")
    private Output<String> tenancyOcid;

    /**
     * @return (Updatable) Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Output<String> tenancyOcid() {
        return this.tenancyOcid;
    }
    /**
     * (Updatable) Oracle Cloud Infrastructure Tags.
     * 
     */
    @Export(name="urnietfparamsscimschemasoracleidcsextensionOciTags", refs={DomainsGroupUrnietfparamsscimschemasoracleidcsextensionOciTags.class}, tree="[0]")
    private Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensionOciTags> urnietfparamsscimschemasoracleidcsextensionOciTags;

    /**
     * @return (Updatable) Oracle Cloud Infrastructure Tags.
     * 
     */
    public Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensionOciTags> urnietfparamsscimschemasoracleidcsextensionOciTags() {
        return this.urnietfparamsscimschemasoracleidcsextensionOciTags;
    }
    /**
     * (Updatable) Schema for Database Service  Resource
     * 
     */
    @Export(name="urnietfparamsscimschemasoracleidcsextensiondbcsGroups", refs={List.class,DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroup.class}, tree="[0,1]")
    private Output<List<DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroup>> urnietfparamsscimschemasoracleidcsextensiondbcsGroups;

    /**
     * @return (Updatable) Schema for Database Service  Resource
     * 
     */
    public Output<List<DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroup>> urnietfparamsscimschemasoracleidcsextensiondbcsGroups() {
        return this.urnietfparamsscimschemasoracleidcsextensiondbcsGroups;
    }
    /**
     * (Updatable) Dynamic Group
     * 
     */
    @Export(name="urnietfparamsscimschemasoracleidcsextensiondynamicGroup", refs={DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondynamicGroup.class}, tree="[0]")
    private Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondynamicGroup> urnietfparamsscimschemasoracleidcsextensiondynamicGroup;

    /**
     * @return (Updatable) Dynamic Group
     * 
     */
    public Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondynamicGroup> urnietfparamsscimschemasoracleidcsextensiondynamicGroup() {
        return this.urnietfparamsscimschemasoracleidcsextensiondynamicGroup;
    }
    /**
     * (Updatable) Oracle Identity Cloud Service Group
     * 
     */
    @Export(name="urnietfparamsscimschemasoracleidcsextensiongroupGroup", refs={DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroup.class}, tree="[0]")
    private Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroup> urnietfparamsscimschemasoracleidcsextensiongroupGroup;

    /**
     * @return (Updatable) Oracle Identity Cloud Service Group
     * 
     */
    public Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroup> urnietfparamsscimschemasoracleidcsextensiongroupGroup() {
        return this.urnietfparamsscimschemasoracleidcsextensiongroupGroup;
    }
    /**
     * (Updatable) POSIX Group extension
     * 
     */
    @Export(name="urnietfparamsscimschemasoracleidcsextensionposixGroup", refs={DomainsGroupUrnietfparamsscimschemasoracleidcsextensionposixGroup.class}, tree="[0]")
    private Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensionposixGroup> urnietfparamsscimschemasoracleidcsextensionposixGroup;

    /**
     * @return (Updatable) POSIX Group extension
     * 
     */
    public Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensionposixGroup> urnietfparamsscimschemasoracleidcsextensionposixGroup() {
        return this.urnietfparamsscimschemasoracleidcsextensionposixGroup;
    }
    /**
     * (Updatable) Requestable Group
     * 
     */
    @Export(name="urnietfparamsscimschemasoracleidcsextensionrequestableGroup", refs={DomainsGroupUrnietfparamsscimschemasoracleidcsextensionrequestableGroup.class}, tree="[0]")
    private Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensionrequestableGroup> urnietfparamsscimschemasoracleidcsextensionrequestableGroup;

    /**
     * @return (Updatable) Requestable Group
     * 
     */
    public Output<DomainsGroupUrnietfparamsscimschemasoracleidcsextensionrequestableGroup> urnietfparamsscimschemasoracleidcsextensionrequestableGroup() {
        return this.urnietfparamsscimschemasoracleidcsextensionrequestableGroup;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public DomainsGroup(java.lang.String name) {
        this(name, DomainsGroupArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public DomainsGroup(java.lang.String name, DomainsGroupArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public DomainsGroup(java.lang.String name, DomainsGroupArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Identity/domainsGroup:DomainsGroup", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private DomainsGroup(java.lang.String name, Output<java.lang.String> id, @Nullable DomainsGroupState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Identity/domainsGroup:DomainsGroup", name, state, makeResourceOptions(options, id), false);
    }

    private static DomainsGroupArgs makeArgs(DomainsGroupArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? DomainsGroupArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static DomainsGroup get(java.lang.String name, Output<java.lang.String> id, @Nullable DomainsGroupState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new DomainsGroup(name, id, state, options);
    }
}
