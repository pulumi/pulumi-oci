// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Identity.DomainsAppRoleArgs;
import com.pulumi.oci.Identity.inputs.DomainsAppRoleState;
import com.pulumi.oci.Identity.outputs.DomainsAppRoleApp;
import com.pulumi.oci.Identity.outputs.DomainsAppRoleIdcsCreatedBy;
import com.pulumi.oci.Identity.outputs.DomainsAppRoleIdcsLastModifiedBy;
import com.pulumi.oci.Identity.outputs.DomainsAppRoleMember;
import com.pulumi.oci.Identity.outputs.DomainsAppRoleMeta;
import com.pulumi.oci.Identity.outputs.DomainsAppRoleTag;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the App Role resource in Oracle Cloud Infrastructure Identity Domains service.
 * 
 * Create an AppRole
 * 
 * ## Example Usage
 * 
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.Identity.DomainsAppRole;
 * import com.pulumi.oci.Identity.DomainsAppRoleArgs;
 * import com.pulumi.oci.Identity.inputs.DomainsAppRoleAppArgs;
 * import com.pulumi.oci.Identity.inputs.DomainsAppRoleTagArgs;
 * import java.util.List;
 * import java.util.ArrayList;
 * import java.util.Map;
 * import java.io.File;
 * import java.nio.file.Files;
 * import java.nio.file.Paths;
 * 
 * public class App {
 *     public static void main(String[] args) {
 *         Pulumi.run(App::stack);
 *     }
 * 
 *     public static void stack(Context ctx) {
 *         var testAppRole = new DomainsAppRole(&#34;testAppRole&#34;, DomainsAppRoleArgs.builder()        
 *             .app(DomainsAppRoleAppArgs.builder()
 *                 .value(oci_identity_domains_app.test_app().id())
 *                 .build())
 *             .displayName(var_.app_role_display_name())
 *             .idcsEndpoint(data.oci_identity_domain().test_domain().url())
 *             .schemas(&#34;urn:ietf:params:scim:schemas:oracle:idcs:AppRole&#34;)
 *             .adminRole(var_.app_role_admin_role())
 *             .attributeSets(&#34;all&#34;)
 *             .attributes(&#34;&#34;)
 *             .authorization(var_.app_role_authorization())
 *             .availableToClients(var_.app_role_available_to_clients())
 *             .availableToGroups(var_.app_role_available_to_groups())
 *             .availableToUsers(var_.app_role_available_to_users())
 *             .description(var_.app_role_description())
 *             .id(var_.app_role_id())
 *             .legacyGroupName(&#34;legacyGroupName&#34;)
 *             .ocid(var_.app_role_ocid())
 *             .public_(var_.app_role_public())
 *             .resourceTypeSchemaVersion(var_.app_role_resource_type_schema_version())
 *             .tags(DomainsAppRoleTagArgs.builder()
 *                 .key(var_.app_role_tags_key())
 *                 .value(var_.app_role_tags_value())
 *                 .build())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * AppRoles can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Identity/domainsAppRole:DomainsAppRole test_app_role &#34;idcsEndpoint/{idcsEndpoint}/appRoles/{appRoleId}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Identity/domainsAppRole:DomainsAppRole")
public class DomainsAppRole extends com.pulumi.resources.CustomResource {
    /**
     * If true, the role provides administrative access privileges.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    @Export(name="adminRole", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> adminRole;

    /**
     * @return If true, the role provides administrative access privileges.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    public Output<Boolean> adminRole() {
        return this.adminRole;
    }
    /**
     * A unique identifier for the application that references this role.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * idcsCsvAttributeNameMappings: [[columnHeaderName:App Name, mapsTo:app.display]]
     * * multiValued: false
     * * mutability: immutable
     * * required: true
     * * returned: default
     * * type: complex
     * * uniqueness: none
     * 
     */
    @Export(name="app", refs={DomainsAppRoleApp.class}, tree="[0]")
    private Output<DomainsAppRoleApp> app;

    /**
     * @return A unique identifier for the application that references this role.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * idcsCsvAttributeNameMappings: [[columnHeaderName:App Name, mapsTo:app.display]]
     * * multiValued: false
     * * mutability: immutable
     * * required: true
     * * returned: default
     * * type: complex
     * * uniqueness: none
     * 
     */
    public Output<DomainsAppRoleApp> app() {
        return this.app;
    }
    /**
     * A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If &#39;attributes&#39; query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
     * 
     */
    @Export(name="attributeSets", refs={List.class,String.class}, tree="[0,1]")
    private Output</* @Nullable */ List<String>> attributeSets;

    /**
     * @return A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If &#39;attributes&#39; query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
     * 
     */
    public Output<Optional<List<String>>> attributeSets() {
        return Codegen.optional(this.attributeSets);
    }
    /**
     * A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
     * 
     */
    @Export(name="attributes", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> attributes;

    /**
     * @return A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
     * 
     */
    public Output<Optional<String>> attributes() {
        return Codegen.optional(this.attributes);
    }
    /**
     * The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     * 
     */
    @Export(name="authorization", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> authorization;

    /**
     * @return The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     * 
     */
    public Output<Optional<String>> authorization() {
        return Codegen.optional(this.authorization);
    }
    /**
     * If true, this AppRole can be granted to Apps.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    @Export(name="availableToClients", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> availableToClients;

    /**
     * @return If true, this AppRole can be granted to Apps.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    public Output<Boolean> availableToClients() {
        return this.availableToClients;
    }
    /**
     * If true, this AppRole can be granted to Groups.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    @Export(name="availableToGroups", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> availableToGroups;

    /**
     * @return If true, this AppRole can be granted to Groups.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    public Output<Boolean> availableToGroups() {
        return this.availableToGroups;
    }
    /**
     * If true, this AppRole can be granted to Users.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    @Export(name="availableToUsers", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> availableToUsers;

    /**
     * @return If true, this AppRole can be granted to Users.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    public Output<Boolean> availableToUsers() {
        return this.availableToUsers;
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
     * AppRole description
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
    @Export(name="description", refs={String.class}, tree="[0]")
    private Output<String> description;

    /**
     * @return AppRole description
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
    public Output<String> description() {
        return this.description;
    }
    /**
     * AppRole name
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsCsvAttributeName: Display Name
     * * idcsCsvAttributeNameMappings: [[columnHeaderName:Entitlement Value]]
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: true
     * * returned: always
     * * type: string
     * * uniqueness: none
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return AppRole name
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsCsvAttributeName: Display Name
     * * idcsCsvAttributeNameMappings: [[columnHeaderName:Entitlement Value]]
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: true
     * * returned: always
     * * type: string
     * * uniqueness: none
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
    @Export(name="idcsCreatedBies", refs={List.class,DomainsAppRoleIdcsCreatedBy.class}, tree="[0,1]")
    private Output<List<DomainsAppRoleIdcsCreatedBy>> idcsCreatedBies;

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
    public Output<List<DomainsAppRoleIdcsCreatedBy>> idcsCreatedBies() {
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
    @Export(name="idcsLastModifiedBies", refs={List.class,DomainsAppRoleIdcsLastModifiedBy.class}, tree="[0,1]")
    private Output<List<DomainsAppRoleIdcsLastModifiedBy>> idcsLastModifiedBies;

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
    public Output<List<DomainsAppRoleIdcsLastModifiedBy>> idcsLastModifiedBies() {
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
     * The name of the legacy group associated with this AppRole.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: server
     * 
     */
    @Export(name="legacyGroupName", refs={String.class}, tree="[0]")
    private Output<String> legacyGroupName;

    /**
     * @return The name of the legacy group associated with this AppRole.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: server
     * 
     */
    public Output<String> legacyGroupName() {
        return this.legacyGroupName;
    }
    /**
     * (Updatable) If true, indicates that this Oracle Identity Cloud Service AppRole can be granted to a delegated administrator whose scope is limited to users that are members of one or more groups.
     * 
     * **Added In:** 19.2.1
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    @Export(name="limitedToOneOrMoreGroups", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> limitedToOneOrMoreGroups;

    /**
     * @return (Updatable) If true, indicates that this Oracle Identity Cloud Service AppRole can be granted to a delegated administrator whose scope is limited to users that are members of one or more groups.
     * 
     * **Added In:** 19.2.1
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    public Output<Boolean> limitedToOneOrMoreGroups() {
        return this.limitedToOneOrMoreGroups;
    }
    /**
     * (Updatable) AppRole localization name
     * 
     * **Added In:** 2109090424
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
    @Export(name="localizedDisplayName", refs={String.class}, tree="[0]")
    private Output<String> localizedDisplayName;

    /**
     * @return (Updatable) AppRole localization name
     * 
     * **Added In:** 2109090424
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
    public Output<String> localizedDisplayName() {
        return this.localizedDisplayName;
    }
    /**
     * (Updatable) AppRole members - when requesting members attribute, it is recommended to use startIndex and count to return members in pages instead of in a single response, eg : #attributes=members[startIndex=1%26count=10]
     * 
     * **SCIM++ Properties:**
     * * idcsCompositeKey: [value, type]
     * * idcsCsvAttributeNameMappings: [[columnHeaderName:Grantee Name, mapsTo:members.value], [columnHeaderName:Grantee Type, mapsTo:members.type]]
     * * idcsSearchable: true
     * * multiValued: true
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * idcsPaginateResponse: true
     * * type: complex
     * * uniqueness: none
     * 
     */
    @Export(name="members", refs={List.class,DomainsAppRoleMember.class}, tree="[0,1]")
    private Output<List<DomainsAppRoleMember>> members;

    /**
     * @return (Updatable) AppRole members - when requesting members attribute, it is recommended to use startIndex and count to return members in pages instead of in a single response, eg : #attributes=members[startIndex=1%26count=10]
     * 
     * **SCIM++ Properties:**
     * * idcsCompositeKey: [value, type]
     * * idcsCsvAttributeNameMappings: [[columnHeaderName:Grantee Name, mapsTo:members.value], [columnHeaderName:Grantee Type, mapsTo:members.type]]
     * * idcsSearchable: true
     * * multiValued: true
     * * mutability: readOnly
     * * required: false
     * * returned: request
     * * idcsPaginateResponse: true
     * * type: complex
     * * uniqueness: none
     * 
     */
    public Output<List<DomainsAppRoleMember>> members() {
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
    @Export(name="metas", refs={List.class,DomainsAppRoleMeta.class}, tree="[0,1]")
    private Output<List<DomainsAppRoleMeta>> metas;

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
    public Output<List<DomainsAppRoleMeta>> metas() {
        return this.metas;
    }
    /**
     * Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
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
     * @return Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
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
     * If true, this AppRole is available automatically to every Oracle Identity Cloud Service User in this tenancy. There is no need to grant it to individual Users or Groups.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    @Export(name="public", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> public_;

    /**
     * @return If true, this AppRole is available automatically to every Oracle Identity Cloud Service User in this tenancy. There is no need to grant it to individual Users or Groups.
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: boolean
     * * uniqueness: none
     * 
     */
    public Output<Boolean> public_() {
        return this.public_;
    }
    /**
     * An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     * 
     */
    @Export(name="resourceTypeSchemaVersion", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> resourceTypeSchemaVersion;

    /**
     * @return An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     * 
     */
    public Output<Optional<String>> resourceTypeSchemaVersion() {
        return Codegen.optional(this.resourceTypeSchemaVersion);
    }
    /**
     * REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
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
     * @return REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
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
     * A list of tags on this resource.
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
    @Export(name="tags", refs={List.class,DomainsAppRoleTag.class}, tree="[0,1]")
    private Output<List<DomainsAppRoleTag>> tags;

    /**
     * @return A list of tags on this resource.
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
    public Output<List<DomainsAppRoleTag>> tags() {
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
     * (Updatable) AppRole unique name
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: always
     * * type: string
     * * uniqueness: server
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="uniqueName", refs={String.class}, tree="[0]")
    private Output<String> uniqueName;

    /**
     * @return (Updatable) AppRole unique name
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: always
     * * type: string
     * * uniqueness: server
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> uniqueName() {
        return this.uniqueName;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public DomainsAppRole(String name) {
        this(name, DomainsAppRoleArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public DomainsAppRole(String name, DomainsAppRoleArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public DomainsAppRole(String name, DomainsAppRoleArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Identity/domainsAppRole:DomainsAppRole", name, args == null ? DomainsAppRoleArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private DomainsAppRole(String name, Output<String> id, @Nullable DomainsAppRoleState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Identity/domainsAppRole:DomainsAppRole", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
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
    public static DomainsAppRole get(String name, Output<String> id, @Nullable DomainsAppRoleState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new DomainsAppRole(name, id, state, options);
    }
}