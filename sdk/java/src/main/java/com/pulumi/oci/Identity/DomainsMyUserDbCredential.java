// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Identity.DomainsMyUserDbCredentialArgs;
import com.pulumi.oci.Identity.inputs.DomainsMyUserDbCredentialState;
import com.pulumi.oci.Identity.outputs.DomainsMyUserDbCredentialIdcsCreatedBy;
import com.pulumi.oci.Identity.outputs.DomainsMyUserDbCredentialIdcsLastModifiedBy;
import com.pulumi.oci.Identity.outputs.DomainsMyUserDbCredentialMeta;
import com.pulumi.oci.Identity.outputs.DomainsMyUserDbCredentialTag;
import com.pulumi.oci.Identity.outputs.DomainsMyUserDbCredentialUser;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the My User Db Credential resource in Oracle Cloud Infrastructure Identity Domains service.
 * 
 * Set a User&#39;s DbCredential
 * 
 * ## Example Usage
 * 
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.Identity.DomainsMyUserDbCredential;
 * import com.pulumi.oci.Identity.DomainsMyUserDbCredentialArgs;
 * import com.pulumi.oci.Identity.inputs.DomainsMyUserDbCredentialTagArgs;
 * import com.pulumi.oci.Identity.inputs.DomainsMyUserDbCredentialUserArgs;
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
 *         var testMyUserDbCredential = new DomainsMyUserDbCredential(&#34;testMyUserDbCredential&#34;, DomainsMyUserDbCredentialArgs.builder()        
 *             .dbPassword(var_.my_user_db_credential_db_password())
 *             .idcsEndpoint(data.oci_identity_domain().test_domain().url())
 *             .schemas(&#34;urn:ietf:params:scim:schemas:oracle:idcs:UserDbCredentials&#34;)
 *             .authorization(var_.my_user_db_credential_authorization())
 *             .description(var_.my_user_db_credential_description())
 *             .expiresOn(var_.my_user_db_credential_expires_on())
 *             .id(var_.my_user_db_credential_id())
 *             .ocid(var_.my_user_db_credential_ocid())
 *             .resourceTypeSchemaVersion(var_.my_user_db_credential_resource_type_schema_version())
 *             .status(var_.my_user_db_credential_status())
 *             .tags(DomainsMyUserDbCredentialTagArgs.builder()
 *                 .key(var_.my_user_db_credential_tags_key())
 *                 .value(var_.my_user_db_credential_tags_value())
 *                 .build())
 *             .user(DomainsMyUserDbCredentialUserArgs.builder()
 *                 .value(var_.my_user_db_credential_user_value())
 *                 .ocid(var_.my_user_db_credential_user_ocid())
 *                 .build())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * MyUserDbCredentials can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Identity/domainsMyUserDbCredential:DomainsMyUserDbCredential test_my_user_db_credential &#34;idcsEndpoint/{idcsEndpoint}/myUserDbCredentials/{myUserDbCredentialId}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Identity/domainsMyUserDbCredential:DomainsMyUserDbCredential")
public class DomainsMyUserDbCredential extends com.pulumi.resources.CustomResource {
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
     * The db password of the user
     * 
     */
    @Export(name="dbPassword", type=String.class, parameters={})
    private Output<String> dbPassword;

    /**
     * @return The db password of the user
     * 
     */
    public Output<String> dbPassword() {
        return this.dbPassword;
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
     * (Updatable) Indicates that the db password has expired
     * 
     */
    @Export(name="expired", type=Boolean.class, parameters={})
    private Output<Boolean> expired;

    /**
     * @return (Updatable) Indicates that the db password has expired
     * 
     */
    public Output<Boolean> expired() {
        return this.expired;
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
    @Export(name="idcsCreatedBies", type=List.class, parameters={DomainsMyUserDbCredentialIdcsCreatedBy.class})
    private Output<List<DomainsMyUserDbCredentialIdcsCreatedBy>> idcsCreatedBies;

    /**
     * @return (Updatable) The User or App who created the Resource
     * 
     */
    public Output<List<DomainsMyUserDbCredentialIdcsCreatedBy>> idcsCreatedBies() {
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
    @Export(name="idcsLastModifiedBies", type=List.class, parameters={DomainsMyUserDbCredentialIdcsLastModifiedBy.class})
    private Output<List<DomainsMyUserDbCredentialIdcsLastModifiedBy>> idcsLastModifiedBies;

    /**
     * @return (Updatable) The User or App who modified the Resource
     * 
     */
    public Output<List<DomainsMyUserDbCredentialIdcsLastModifiedBy>> idcsLastModifiedBies() {
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
     * (Updatable) A DateTime that specifies the date and time when the current db password was set
     * 
     */
    @Export(name="lastSetDate", type=String.class, parameters={})
    private Output<String> lastSetDate;

    /**
     * @return (Updatable) A DateTime that specifies the date and time when the current db password was set
     * 
     */
    public Output<String> lastSetDate() {
        return this.lastSetDate;
    }
    /**
     * (Updatable) A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    @Export(name="metas", type=List.class, parameters={DomainsMyUserDbCredentialMeta.class})
    private Output<List<DomainsMyUserDbCredentialMeta>> metas;

    /**
     * @return (Updatable) A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     * 
     */
    public Output<List<DomainsMyUserDbCredentialMeta>> metas() {
        return this.metas;
    }
    /**
     * (Updatable) The db password of the user with mixed salt
     * 
     */
    @Export(name="mixedDbPassword", type=String.class, parameters={})
    private Output<String> mixedDbPassword;

    /**
     * @return (Updatable) The db password of the user with mixed salt
     * 
     */
    public Output<String> mixedDbPassword() {
        return this.mixedDbPassword;
    }
    /**
     * (Updatable) The mixed salt of the password
     * 
     */
    @Export(name="mixedSalt", type=String.class, parameters={})
    private Output<String> mixedSalt;

    /**
     * @return (Updatable) The mixed salt of the password
     * 
     */
    public Output<String> mixedSalt() {
        return this.mixedSalt;
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
     * (Updatable) The salt of the password
     * 
     */
    @Export(name="salt", type=String.class, parameters={})
    private Output<String> salt;

    /**
     * @return (Updatable) The salt of the password
     * 
     */
    public Output<String> salt() {
        return this.salt;
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
    @Export(name="tags", type=List.class, parameters={DomainsMyUserDbCredentialTag.class})
    private Output<List<DomainsMyUserDbCredentialTag>> tags;

    /**
     * @return A list of tags on this resource.
     * 
     */
    public Output<List<DomainsMyUserDbCredentialTag>> tags() {
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
     * User linked to db credential
     * 
     */
    @Export(name="user", type=DomainsMyUserDbCredentialUser.class, parameters={})
    private Output<DomainsMyUserDbCredentialUser> user;

    /**
     * @return User linked to db credential
     * 
     */
    public Output<DomainsMyUserDbCredentialUser> user() {
        return this.user;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public DomainsMyUserDbCredential(String name) {
        this(name, DomainsMyUserDbCredentialArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public DomainsMyUserDbCredential(String name, DomainsMyUserDbCredentialArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public DomainsMyUserDbCredential(String name, DomainsMyUserDbCredentialArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Identity/domainsMyUserDbCredential:DomainsMyUserDbCredential", name, args == null ? DomainsMyUserDbCredentialArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private DomainsMyUserDbCredential(String name, Output<String> id, @Nullable DomainsMyUserDbCredentialState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Identity/domainsMyUserDbCredential:DomainsMyUserDbCredential", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .additionalSecretOutputs(List.of(
                "dbPassword"
            ))
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
    public static DomainsMyUserDbCredential get(String name, Output<String> id, @Nullable DomainsMyUserDbCredentialState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new DomainsMyUserDbCredential(name, id, state, options);
    }
}