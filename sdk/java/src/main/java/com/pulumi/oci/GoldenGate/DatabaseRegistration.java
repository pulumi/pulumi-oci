// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.GoldenGate.DatabaseRegistrationArgs;
import com.pulumi.oci.GoldenGate.inputs.DatabaseRegistrationState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Database Registration resource in Oracle Cloud Infrastructure Golden Gate service.
 * 
 * Note: Deprecated. Use the /connections API instead.
 * Creates a new DatabaseRegistration.
 * 
 * ## Example Usage
 * 
 * &lt;!--Start PulumiCodeChooser --&gt;
 * <pre>
 * {@code
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.GoldenGate.DatabaseRegistration;
 * import com.pulumi.oci.GoldenGate.DatabaseRegistrationArgs;
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
 *         var testDatabaseRegistration = new DatabaseRegistration("testDatabaseRegistration", DatabaseRegistrationArgs.builder()
 *             .aliasName(databaseRegistrationAliasName)
 *             .compartmentId(compartmentId)
 *             .displayName(databaseRegistrationDisplayName)
 *             .fqdn(databaseRegistrationFqdn)
 *             .password(databaseRegistrationPassword)
 *             .username(databaseRegistrationUsername)
 *             .connectionString(databaseRegistrationConnectionString)
 *             .databaseId(testDatabase.id())
 *             .definedTags(Map.of("foo-namespace.bar-key", "value"))
 *             .description(databaseRegistrationDescription)
 *             .freeformTags(Map.of("bar-key", "value"))
 *             .ipAddress(databaseRegistrationIpAddress)
 *             .keyId(testKey.id())
 *             .secretCompartmentId(testCompartment.id())
 *             .sessionMode(databaseRegistrationSessionMode)
 *             .subnetId(testSubnet.id())
 *             .vaultId(testVault.id())
 *             .wallet(databaseRegistrationWallet)
 *             .build());
 * 
 *     }
 * }
 * }
 * </pre>
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 * ## Import
 * 
 * DatabaseRegistrations can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:GoldenGate/databaseRegistration:DatabaseRegistration test_database_registration &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:GoldenGate/databaseRegistration:DatabaseRegistration")
public class DatabaseRegistration extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) Credential store alias.
     * 
     */
    @Export(name="aliasName", refs={String.class}, tree="[0]")
    private Output<String> aliasName;

    /**
     * @return (Updatable) Credential store alias.
     * 
     */
    public Output<String> aliasName() {
        return this.aliasName;
    }
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Connect descriptor or Easy Connect Naming method used to connect to a database.
     * 
     */
    @Export(name="connectionString", refs={String.class}, tree="[0]")
    private Output<String> connectionString;

    /**
     * @return (Updatable) Connect descriptor or Easy Connect Naming method used to connect to a database.
     * 
     */
    public Output<String> connectionString() {
        return this.connectionString;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database being referenced.
     * 
     */
    @Export(name="databaseId", refs={String.class}, tree="[0]")
    private Output<String> databaseId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database being referenced.
     * 
     */
    public Output<String> databaseId() {
        return this.databaseId;
    }
    /**
     * (Updatable) Tags defined for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Tags defined for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) Metadata about this specific object.
     * 
     */
    @Export(name="description", refs={String.class}, tree="[0]")
    private Output<String> description;

    /**
     * @return (Updatable) Metadata about this specific object.
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) An object&#39;s Display Name.
     * 
     */
    @Export(name="displayName", refs={String.class}, tree="[0]")
    private Output<String> displayName;

    /**
     * @return (Updatable) An object&#39;s Display Name.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) A three-label Fully Qualified Domain Name (FQDN) for a resource.
     * 
     */
    @Export(name="fqdn", refs={String.class}, tree="[0]")
    private Output<String> fqdn;

    /**
     * @return (Updatable) A three-label Fully Qualified Domain Name (FQDN) for a resource.
     * 
     */
    public Output<String> fqdn() {
        return this.fqdn;
    }
    /**
     * (Updatable) A simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only.  Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) A simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only.  Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * The private IP address in the customer&#39;s VCN of the customer&#39;s endpoint, typically a database.
     * 
     */
    @Export(name="ipAddress", refs={String.class}, tree="[0]")
    private Output<String> ipAddress;

    /**
     * @return The private IP address in the customer&#39;s VCN of the customer&#39;s endpoint, typically a database.
     * 
     */
    public Output<String> ipAddress() {
        return this.ipAddress;
    }
    /**
     * Refers to the customer&#39;s master key OCID.  If provided, it references a key to manage secrets. Customers must add policies to permit GoldenGate to use this key.
     * 
     */
    @Export(name="keyId", refs={String.class}, tree="[0]")
    private Output<String> keyId;

    /**
     * @return Refers to the customer&#39;s master key OCID.  If provided, it references a key to manage secrets. Customers must add policies to permit GoldenGate to use this key.
     * 
     */
    public Output<String> keyId() {
        return this.keyId;
    }
    /**
     * Describes the object&#39;s current state in detail. For example, it can be used to provide actionable information for a resource in a Failed state.
     * 
     */
    @Export(name="lifecycleDetails", refs={String.class}, tree="[0]")
    private Output<String> lifecycleDetails;

    /**
     * @return Describes the object&#39;s current state in detail. For example, it can be used to provide actionable information for a resource in a Failed state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * (Updatable) The password Oracle GoldenGate uses to connect the associated system of the given technology. It must conform to the specific security requirements including length, case sensitivity, and so on. Deprecated: This field is deprecated and replaced by &#34;passwordSecretId&#34;. This field will be removed after February 15 2026.
     * 
     */
    @Export(name="password", refs={String.class}, tree="[0]")
    private Output<String> password;

    /**
     * @return (Updatable) The password Oracle GoldenGate uses to connect the associated system of the given technology. It must conform to the specific security requirements including length, case sensitivity, and so on. Deprecated: This field is deprecated and replaced by &#34;passwordSecretId&#34;. This field will be removed after February 15 2026.
     * 
     */
    public Output<String> password() {
        return this.password;
    }
    /**
     * A Private Endpoint IP address created in the customer&#39;s subnet.  A customer database can expect network traffic initiated by GoldenGate Service from this IP address.  It can also send network traffic to this IP address, typically in response to requests from GoldenGate Service.  The customer may use this IP address in Security Lists or Network Security Groups (NSG) as needed.
     * 
     */
    @Export(name="rcePrivateIp", refs={String.class}, tree="[0]")
    private Output<String> rcePrivateIp;

    /**
     * @return A Private Endpoint IP address created in the customer&#39;s subnet.  A customer database can expect network traffic initiated by GoldenGate Service from this IP address.  It can also send network traffic to this IP address, typically in response to requests from GoldenGate Service.  The customer may use this IP address in Security Lists or Network Security Groups (NSG) as needed.
     * 
     */
    public Output<String> rcePrivateIp() {
        return this.rcePrivateIp;
    }
    /**
     * The OCID of the compartment where the GoldenGate Secret will be created.  If provided, it references a key to manage secrets. Customers must add policies to permit GoldenGate to use this key.
     * 
     */
    @Export(name="secretCompartmentId", refs={String.class}, tree="[0]")
    private Output<String> secretCompartmentId;

    /**
     * @return The OCID of the compartment where the GoldenGate Secret will be created.  If provided, it references a key to manage secrets. Customers must add policies to permit GoldenGate to use this key.
     * 
     */
    public Output<String> secretCompartmentId() {
        return this.secretCompartmentId;
    }
    /**
     * The OCID of the customer&#39;s GoldenGate Service Secret.  If provided, it references a key that customers will be required to ensure the policies are established  to permit GoldenGate to use this Secret.
     * 
     */
    @Export(name="secretId", refs={String.class}, tree="[0]")
    private Output<String> secretId;

    /**
     * @return The OCID of the customer&#39;s GoldenGate Service Secret.  If provided, it references a key that customers will be required to ensure the policies are established  to permit GoldenGate to use this Secret.
     * 
     */
    public Output<String> secretId() {
        return this.secretId;
    }
    /**
     * (Updatable) The mode of the database connection session to be established by the data client. &#39;REDIRECT&#39; - for a RAC database, &#39;DIRECT&#39; - for a non-RAC database. Connection to a RAC database involves a redirection received from the SCAN listeners to the database node to connect to. By default the mode would be DIRECT.
     * 
     */
    @Export(name="sessionMode", refs={String.class}, tree="[0]")
    private Output<String> sessionMode;

    /**
     * @return (Updatable) The mode of the database connection session to be established by the data client. &#39;REDIRECT&#39; - for a RAC database, &#39;DIRECT&#39; - for a non-RAC database. Connection to a RAC database involves a redirection received from the SCAN listeners to the database node to connect to. By default the mode would be DIRECT.
     * 
     */
    public Output<String> sessionMode() {
        return this.sessionMode;
    }
    /**
     * Possible lifecycle states.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return Possible lifecycle states.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the target subnet of the dedicated connection.
     * 
     */
    @Export(name="subnetId", refs={String.class}, tree="[0]")
    private Output<String> subnetId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the target subnet of the dedicated connection.
     * 
     */
    public Output<String> subnetId() {
        return this.subnetId;
    }
    /**
     * The system tags associated with this resource, if any. The system tags are set by Oracle Cloud Infrastructure services. Each key is predefined and scoped to namespaces.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{orcl-cloud: {free-tier-retain: true}}`
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> systemTags;

    /**
     * @return The system tags associated with this resource, if any. The system tags are set by Oracle Cloud Infrastructure services. Each key is predefined and scoped to namespaces.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{orcl-cloud: {free-tier-retain: true}}`
     * 
     */
    public Output<Map<String,String>> systemTags() {
        return this.systemTags;
    }
    /**
     * The time the resource was created. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The time the resource was created. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time the resource was last updated. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The time the resource was last updated. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * (Updatable) The username Oracle GoldenGate uses to connect the associated system of the given technology. This username must already exist and be available by the system/application to be connected to and must conform to the case sensitivty requirments defined in it.
     * 
     */
    @Export(name="username", refs={String.class}, tree="[0]")
    private Output<String> username;

    /**
     * @return (Updatable) The username Oracle GoldenGate uses to connect the associated system of the given technology. This username must already exist and be available by the system/application to be connected to and must conform to the case sensitivty requirments defined in it.
     * 
     */
    public Output<String> username() {
        return this.username;
    }
    /**
     * Refers to the customer&#39;s vault OCID.  If provided, it references a vault where GoldenGate can manage secrets. Customers must add policies to permit GoldenGate to manage secrets contained within this vault.
     * 
     */
    @Export(name="vaultId", refs={String.class}, tree="[0]")
    private Output<String> vaultId;

    /**
     * @return Refers to the customer&#39;s vault OCID.  If provided, it references a vault where GoldenGate can manage secrets. Customers must add policies to permit GoldenGate to manage secrets contained within this vault.
     * 
     */
    public Output<String> vaultId() {
        return this.vaultId;
    }
    /**
     * (Updatable) The wallet contents Oracle GoldenGate uses to make connections to a database. This attribute is expected to be base64 encoded. Deprecated: This field is deprecated and replaced by &#34;walletSecretId&#34;. This field will be removed after February 15 2026.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Export(name="wallet", refs={String.class}, tree="[0]")
    private Output<String> wallet;

    /**
     * @return (Updatable) The wallet contents Oracle GoldenGate uses to make connections to a database. This attribute is expected to be base64 encoded. Deprecated: This field is deprecated and replaced by &#34;walletSecretId&#34;. This field will be removed after February 15 2026.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> wallet() {
        return this.wallet;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public DatabaseRegistration(java.lang.String name) {
        this(name, DatabaseRegistrationArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public DatabaseRegistration(java.lang.String name, DatabaseRegistrationArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public DatabaseRegistration(java.lang.String name, DatabaseRegistrationArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:GoldenGate/databaseRegistration:DatabaseRegistration", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private DatabaseRegistration(java.lang.String name, Output<java.lang.String> id, @Nullable DatabaseRegistrationState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:GoldenGate/databaseRegistration:DatabaseRegistration", name, state, makeResourceOptions(options, id), false);
    }

    private static DatabaseRegistrationArgs makeArgs(DatabaseRegistrationArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? DatabaseRegistrationArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .additionalSecretOutputs(List.of(
                "password"
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
    public static DatabaseRegistration get(java.lang.String name, Output<java.lang.String> id, @Nullable DatabaseRegistrationState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new DatabaseRegistration(name, id, state, options);
    }
}
