// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Identity.DomainsMyOauth2clientCredentialArgs;
import com.pulumi.oci.Identity.inputs.DomainsMyOauth2clientCredentialState;
import com.pulumi.oci.Identity.outputs.DomainsMyOauth2clientCredentialIdcsCreatedBy;
import com.pulumi.oci.Identity.outputs.DomainsMyOauth2clientCredentialIdcsLastModifiedBy;
import com.pulumi.oci.Identity.outputs.DomainsMyOauth2clientCredentialMeta;
import com.pulumi.oci.Identity.outputs.DomainsMyOauth2clientCredentialScope;
import com.pulumi.oci.Identity.outputs.DomainsMyOauth2clientCredentialTag;
import com.pulumi.oci.Identity.outputs.DomainsMyOauth2clientCredentialUser;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the My O Auth2 Client Credential resource in Oracle Cloud Infrastructure Identity Domains service.
 * 
 * Add a user&#39;s oauth2 client credential
 * 
 * ## Example Usage
 * 
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.Identity.DomainsMyOauth2clientCredential;
 * import com.pulumi.oci.Identity.DomainsMyOauth2clientCredentialArgs;
 * import com.pulumi.oci.Identity.inputs.DomainsMyOauth2clientCredentialScopeArgs;
 * import com.pulumi.oci.Identity.inputs.DomainsMyOauth2clientCredentialTagArgs;
 * import com.pulumi.oci.Identity.inputs.DomainsMyOauth2clientCredentialUserArgs;
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
 *         var testMyOauth2clientCredential = new DomainsMyOauth2clientCredential(&#34;testMyOauth2clientCredential&#34;, DomainsMyOauth2clientCredentialArgs.builder()        
 *             .idcsEndpoint(data.oci_identity_domain().test_domain().url())
 *             .schemas(&#34;urn:ietf:params:scim:schemas:oracle:idcs:oauth2ClientCredential&#34;)
 *             .scopes(DomainsMyOauth2clientCredentialScopeArgs.builder()
 *                 .audience(var_.my_oauth2client_credential_scopes_audience())
 *                 .scope(var_.my_oauth2client_credential_scopes_scope())
 *                 .build())
 *             .authorization(var_.my_oauth2client_credential_authorization())
 *             .description(var_.my_oauth2client_credential_description())
 *             .expiresOn(var_.my_oauth2client_credential_expires_on())
 *             .id(var_.my_oauth2client_credential_id())
 *             .isResetSecret(var_.my_oauth2client_credential_is_reset_secret())
 *             .ocid(var_.my_oauth2client_credential_ocid())
 *             .resourceTypeSchemaVersion(var_.my_oauth2client_credential_resource_type_schema_version())
 *             .status(var_.my_oauth2client_credential_status())
 *             .tags(DomainsMyOauth2clientCredentialTagArgs.builder()
 *                 .key(var_.my_oauth2client_credential_tags_key())
 *                 .value(var_.my_oauth2client_credential_tags_value())
 *                 .build())
 *             .user(DomainsMyOauth2clientCredentialUserArgs.builder()
 *                 .ocid(var_.my_oauth2client_credential_user_ocid())
 *                 .value(var_.my_oauth2client_credential_user_value())
 *                 .build())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * MyOAuth2ClientCredentials can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Identity/domainsMyOauth2clientCredential:DomainsMyOauth2clientCredential test_my_oauth2client_credential &#34;idcsEndpoint/{idcsEndpoint}/myOAuth2ClientCredentials/{myOAuth2ClientCredentialId}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Identity/domainsMyOauth2clientCredential:DomainsMyOauth2clientCredential")
public class DomainsMyOauth2clientCredential extends com.pulumi.resources.CustomResource {
    /**
     * The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     * 
     */
    @Export(name="authorization", type=String.class, parameters={})
    private Output</* @Nullable */ String> authorization;

    /**
     * @return The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     * 
     */
    public Output<Optional<String>> authorization() {
        return Codegen.optional(this.authorization);
    }
    /**
     * (Updatable) Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
     * 
     */
    @Export(name="compartmentOcid", type=String.class, parameters={})
    private Output<String> compartmentOcid;

    /**
     * @return (Updatable) Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
     * 
     */
    public Output<String> compartmentOcid() {
        return this.compartmentOcid;
    }
    /**
     * (Updatable) A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
     * 
     */
    @Export(name="deleteInProgress", type=Boolean.class, parameters={})
    private Output<Boolean> deleteInProgress;

    /**
     * @return (Updatable) A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
     * 
     */
    public Output<Boolean> deleteInProgress() {
        return this.deleteInProgress;
    }
    /**
     * Description
     * 
     */
    @Export(name="description", type=String.class, parameters={})
    private Output<String> description;

    /**
     * @return Description
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     * 
     */
    @Export(name="domainOcid", type=String.class, parameters={})
    private Output<String> domainOcid;

    /**
     * @return (Updatable) Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     * 
     */
    public Output<String> domainOcid() {
        return this.domainOcid;
    }
    /**
     * User credential expires on
     * 
     */
    @Export(name="expiresOn", type=String.class, parameters={})
    private Output<String> expiresOn;

    /**
     * @return User credential expires on
     * 
     */
    public Output<String> expiresOn() {
        return this.expiresOn;
    }
    /**
     * (Updatable) The User or App who created the Resource
     * 
     */
    @Export(name="idcsCreatedBies", type=List.class, parameters={DomainsMyOauth2clientCredentialIdcsCreatedBy.class})
    private Output<List<DomainsMyOauth2clientCredentialIdcsCreatedBy>> idcsCreatedBies;

    /**
     * @return (Updatable) The User or App who created the Resource
     * 
     */
    public Output<List<DomainsMyOauth2clientCredentialIdcsCreatedBy>> idcsCreatedBies() {
        return this.idcsCreatedBies;
    }
    /**
     * The basic endpoint for the identity domain
     * 
     */
    @Export(name="idcsEndpoint", type=String.class, parameters={})
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
     */
    @Export(name="idcsLastModifiedBies", type=List.class, parameters={DomainsMyOauth2clientCredentialIdcsLastModifiedBy.class})
    private Output<List<DomainsMyOauth2clientCredentialIdcsLastModifiedBy>> idcsLastModifiedBies;

    /**
     * @return (Updatable) The User or App who modified the Resource
     * 
     */
    public Output<List<DomainsMyOauth2clientCredentialIdcsLastModifiedBy>> idcsLastModifiedBies() {
        return this.idcsLastModifiedBies;
    }
    /**
     * (Updatable) The release number when the resource was upgraded.
     * 
     */
    @Export(name="idcsLastUpgradedInRelease", type=String.class, parameters={})
    private Output<String> idcsLastUpgradedInRelease;

    /**
     * @return (Updatable) The release number when the resource was upgraded.
     * 
     */
    public Output<String> idcsLastUpgradedInRelease() {
        return this.idcsLastUpgradedInRelease;
    }
    /**
     * (Updatable) Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
     * 
     */
    @Export(name="idcsPreventedOperations", type=List.class, parameters={String.class})
    private Output<List<String>> idcsPreventedOperations;

    /**
     * @return (Updatable) Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
     * 
     */
    public Output<List<String>> idcsPreventedOperations() {
        return this.idcsPreventedOperations;
    }
    /**
     * Specifies if secret need to be reset
     * 
     */
    @Export(name="isResetSecret", type=Boolean.class, parameters={})
    private Output<Boolean> isResetSecret;

    /**
     * @return Specifies if secret need to be reset
     * 
     */
    public Output<Boolean> isResetSecret() {
        return this.isResetSecret;
    }
    /**
     * (Updatable) A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    @Export(name="metas", type=List.class, parameters={DomainsMyOauth2clientCredentialMeta.class})
    private Output<List<DomainsMyOauth2clientCredentialMeta>> metas;

    /**
     * @return (Updatable) A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    public Output<List<DomainsMyOauth2clientCredentialMeta>> metas() {
        return this.metas;
    }
    /**
     * (Updatable) User name
     * 
     */
    @Export(name="name", type=String.class, parameters={})
    private Output<String> name;

    /**
     * @return (Updatable) User name
     * 
     */
    public Output<String> name() {
        return this.name;
    }
    /**
     * User&#39;s ocid
     * 
     */
    @Export(name="ocid", type=String.class, parameters={})
    private Output<String> ocid;

    /**
     * @return User&#39;s ocid
     * 
     */
    public Output<String> ocid() {
        return this.ocid;
    }
    /**
     * An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     * 
     */
    @Export(name="resourceTypeSchemaVersion", type=String.class, parameters={})
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
     */
    @Export(name="schemas", type=List.class, parameters={String.class})
    private Output<List<String>> schemas;

    /**
     * @return REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \&#34;enterprise\&#34; extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     * 
     */
    public Output<List<String>> schemas() {
        return this.schemas;
    }
    /**
     * Scopes
     * 
     */
    @Export(name="scopes", type=List.class, parameters={DomainsMyOauth2clientCredentialScope.class})
    private Output<List<DomainsMyOauth2clientCredentialScope>> scopes;

    /**
     * @return Scopes
     * 
     */
    public Output<List<DomainsMyOauth2clientCredentialScope>> scopes() {
        return this.scopes;
    }
    /**
     * User credential status
     * 
     */
    @Export(name="status", type=String.class, parameters={})
    private Output<String> status;

    /**
     * @return User credential status
     * 
     */
    public Output<String> status() {
        return this.status;
    }
    /**
     * A list of tags on this resource.
     * 
     */
    @Export(name="tags", type=List.class, parameters={DomainsMyOauth2clientCredentialTag.class})
    private Output<List<DomainsMyOauth2clientCredentialTag>> tags;

    /**
     * @return A list of tags on this resource.
     * 
     */
    public Output<List<DomainsMyOauth2clientCredentialTag>> tags() {
        return this.tags;
    }
    /**
     * (Updatable) Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     * 
     */
    @Export(name="tenancyOcid", type=String.class, parameters={})
    private Output<String> tenancyOcid;

    /**
     * @return (Updatable) Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     * 
     */
    public Output<String> tenancyOcid() {
        return this.tenancyOcid;
    }
    /**
     * User linked to oauth2 client credential
     * 
     */
    @Export(name="user", type=DomainsMyOauth2clientCredentialUser.class, parameters={})
    private Output<DomainsMyOauth2clientCredentialUser> user;

    /**
     * @return User linked to oauth2 client credential
     * 
     */
    public Output<DomainsMyOauth2clientCredentialUser> user() {
        return this.user;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public DomainsMyOauth2clientCredential(String name) {
        this(name, DomainsMyOauth2clientCredentialArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public DomainsMyOauth2clientCredential(String name, DomainsMyOauth2clientCredentialArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public DomainsMyOauth2clientCredential(String name, DomainsMyOauth2clientCredentialArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Identity/domainsMyOauth2clientCredential:DomainsMyOauth2clientCredential", name, args == null ? DomainsMyOauth2clientCredentialArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private DomainsMyOauth2clientCredential(String name, Output<String> id, @Nullable DomainsMyOauth2clientCredentialState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Identity/domainsMyOauth2clientCredential:DomainsMyOauth2clientCredential", name, state, makeResourceOptions(options, id));
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
    public static DomainsMyOauth2clientCredential get(String name, Output<String> id, @Nullable DomainsMyOauth2clientCredentialState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new DomainsMyOauth2clientCredential(name, id, state, options);
    }
}