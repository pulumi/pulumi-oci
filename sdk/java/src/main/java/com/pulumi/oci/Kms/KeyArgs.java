// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Kms.inputs.KeyKeyShapeArgs;
import com.pulumi.oci.Kms.inputs.KeyRestoreFromFileArgs;
import com.pulumi.oci.Kms.inputs.KeyRestoreFromObjectStoreArgs;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class KeyArgs extends com.pulumi.resources.ResourceArgs {

    public static final KeyArgs Empty = new KeyArgs();

    /**
     * (Updatable) The OCID of the compartment where you want to create the master encryption key.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment where you want to create the master encryption key.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Desired state of the key. Possible values : `ENABLED` or `DISABLED`
     * 
     */
    @Import(name="desiredState")
    private @Nullable Output<String> desiredState;

    /**
     * @return (Updatable) Desired state of the key. Possible values : `ENABLED` or `DISABLED`
     * 
     */
    public Optional<Output<String>> desiredState() {
        return Optional.ofNullable(this.desiredState);
    }

    /**
     * (Updatable) A user-friendly name for the key. It does not have to be unique, and it is changeable. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name for the key. It does not have to be unique, and it is changeable. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * The cryptographic properties of a key.
     * 
     */
    @Import(name="keyShape", required=true)
    private Output<KeyKeyShapeArgs> keyShape;

    /**
     * @return The cryptographic properties of a key.
     * 
     */
    public Output<KeyKeyShapeArgs> keyShape() {
        return this.keyShape;
    }

    /**
     * The service endpoint to perform management operations against. Management operations include &#39;Create,&#39; &#39;Update,&#39; &#39;List,&#39; &#39;Get,&#39; and &#39;Delete&#39; operations. See Vault Management endpoint.
     * 
     */
    @Import(name="managementEndpoint", required=true)
    private Output<String> managementEndpoint;

    /**
     * @return The service endpoint to perform management operations against. Management operations include &#39;Create,&#39; &#39;Update,&#39; &#39;List,&#39; &#39;Get,&#39; and &#39;Delete&#39; operations. See Vault Management endpoint.
     * 
     */
    public Output<String> managementEndpoint() {
        return this.managementEndpoint;
    }

    /**
     * The key&#39;s protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault&#39;s RSA wrapping key which persists  on the HSM. All cryptographic operations that use a key with a protection mode of `SOFTWARE` are performed on the server. By default,  a key&#39;s protection mode is set to `HSM`. You can&#39;t change a key&#39;s protection mode after the key is created or imported.
     * 
     */
    @Import(name="protectionMode")
    private @Nullable Output<String> protectionMode;

    /**
     * @return The key&#39;s protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault&#39;s RSA wrapping key which persists  on the HSM. All cryptographic operations that use a key with a protection mode of `SOFTWARE` are performed on the server. By default,  a key&#39;s protection mode is set to `HSM`. You can&#39;t change a key&#39;s protection mode after the key is created or imported.
     * 
     */
    public Optional<Output<String>> protectionMode() {
        return Optional.ofNullable(this.protectionMode);
    }

    /**
     * (Updatable) Details where key was backed up.
     * 
     */
    @Import(name="restoreFromFile")
    private @Nullable Output<KeyRestoreFromFileArgs> restoreFromFile;

    /**
     * @return (Updatable) Details where key was backed up.
     * 
     */
    public Optional<Output<KeyRestoreFromFileArgs>> restoreFromFile() {
        return Optional.ofNullable(this.restoreFromFile);
    }

    /**
     * (Updatable) Details where key was backed up
     * 
     */
    @Import(name="restoreFromObjectStore")
    private @Nullable Output<KeyRestoreFromObjectStoreArgs> restoreFromObjectStore;

    /**
     * @return (Updatable) Details where key was backed up
     * 
     */
    public Optional<Output<KeyRestoreFromObjectStoreArgs>> restoreFromObjectStore() {
        return Optional.ofNullable(this.restoreFromObjectStore);
    }

    /**
     * (Updatable) An optional property when flipped triggers restore from restore option provided in config file.
     * 
     */
    @Import(name="restoreTrigger")
    private @Nullable Output<Boolean> restoreTrigger;

    /**
     * @return (Updatable) An optional property when flipped triggers restore from restore option provided in config file.
     * 
     */
    public Optional<Output<Boolean>> restoreTrigger() {
        return Optional.ofNullable(this.restoreTrigger);
    }

    /**
     * (Updatable) An optional property for the deletion time of the key, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    @Import(name="timeOfDeletion")
    private @Nullable Output<String> timeOfDeletion;

    /**
     * @return (Updatable) An optional property for the deletion time of the key, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeOfDeletion() {
        return Optional.ofNullable(this.timeOfDeletion);
    }

    private KeyArgs() {}

    private KeyArgs(KeyArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.desiredState = $.desiredState;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.keyShape = $.keyShape;
        this.managementEndpoint = $.managementEndpoint;
        this.protectionMode = $.protectionMode;
        this.restoreFromFile = $.restoreFromFile;
        this.restoreFromObjectStore = $.restoreFromObjectStore;
        this.restoreTrigger = $.restoreTrigger;
        this.timeOfDeletion = $.timeOfDeletion;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(KeyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private KeyArgs $;

        public Builder() {
            $ = new KeyArgs();
        }

        public Builder(KeyArgs defaults) {
            $ = new KeyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment where you want to create the master encryption key.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment where you want to create the master encryption key.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param desiredState (Updatable) Desired state of the key. Possible values : `ENABLED` or `DISABLED`
         * 
         * @return builder
         * 
         */
        public Builder desiredState(@Nullable Output<String> desiredState) {
            $.desiredState = desiredState;
            return this;
        }

        /**
         * @param desiredState (Updatable) Desired state of the key. Possible values : `ENABLED` or `DISABLED`
         * 
         * @return builder
         * 
         */
        public Builder desiredState(String desiredState) {
            return desiredState(Output.of(desiredState));
        }

        /**
         * @param displayName (Updatable) A user-friendly name for the key. It does not have to be unique, and it is changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name for the key. It does not have to be unique, and it is changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param keyShape The cryptographic properties of a key.
         * 
         * @return builder
         * 
         */
        public Builder keyShape(Output<KeyKeyShapeArgs> keyShape) {
            $.keyShape = keyShape;
            return this;
        }

        /**
         * @param keyShape The cryptographic properties of a key.
         * 
         * @return builder
         * 
         */
        public Builder keyShape(KeyKeyShapeArgs keyShape) {
            return keyShape(Output.of(keyShape));
        }

        /**
         * @param managementEndpoint The service endpoint to perform management operations against. Management operations include &#39;Create,&#39; &#39;Update,&#39; &#39;List,&#39; &#39;Get,&#39; and &#39;Delete&#39; operations. See Vault Management endpoint.
         * 
         * @return builder
         * 
         */
        public Builder managementEndpoint(Output<String> managementEndpoint) {
            $.managementEndpoint = managementEndpoint;
            return this;
        }

        /**
         * @param managementEndpoint The service endpoint to perform management operations against. Management operations include &#39;Create,&#39; &#39;Update,&#39; &#39;List,&#39; &#39;Get,&#39; and &#39;Delete&#39; operations. See Vault Management endpoint.
         * 
         * @return builder
         * 
         */
        public Builder managementEndpoint(String managementEndpoint) {
            return managementEndpoint(Output.of(managementEndpoint));
        }

        /**
         * @param protectionMode The key&#39;s protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault&#39;s RSA wrapping key which persists  on the HSM. All cryptographic operations that use a key with a protection mode of `SOFTWARE` are performed on the server. By default,  a key&#39;s protection mode is set to `HSM`. You can&#39;t change a key&#39;s protection mode after the key is created or imported.
         * 
         * @return builder
         * 
         */
        public Builder protectionMode(@Nullable Output<String> protectionMode) {
            $.protectionMode = protectionMode;
            return this;
        }

        /**
         * @param protectionMode The key&#39;s protection mode indicates how the key persists and where cryptographic operations that use the key are performed. A protection mode of `HSM` means that the key persists on a hardware security module (HSM) and all cryptographic operations are performed inside the HSM. A protection mode of `SOFTWARE` means that the key persists on the server, protected by the vault&#39;s RSA wrapping key which persists  on the HSM. All cryptographic operations that use a key with a protection mode of `SOFTWARE` are performed on the server. By default,  a key&#39;s protection mode is set to `HSM`. You can&#39;t change a key&#39;s protection mode after the key is created or imported.
         * 
         * @return builder
         * 
         */
        public Builder protectionMode(String protectionMode) {
            return protectionMode(Output.of(protectionMode));
        }

        /**
         * @param restoreFromFile (Updatable) Details where key was backed up.
         * 
         * @return builder
         * 
         */
        public Builder restoreFromFile(@Nullable Output<KeyRestoreFromFileArgs> restoreFromFile) {
            $.restoreFromFile = restoreFromFile;
            return this;
        }

        /**
         * @param restoreFromFile (Updatable) Details where key was backed up.
         * 
         * @return builder
         * 
         */
        public Builder restoreFromFile(KeyRestoreFromFileArgs restoreFromFile) {
            return restoreFromFile(Output.of(restoreFromFile));
        }

        /**
         * @param restoreFromObjectStore (Updatable) Details where key was backed up
         * 
         * @return builder
         * 
         */
        public Builder restoreFromObjectStore(@Nullable Output<KeyRestoreFromObjectStoreArgs> restoreFromObjectStore) {
            $.restoreFromObjectStore = restoreFromObjectStore;
            return this;
        }

        /**
         * @param restoreFromObjectStore (Updatable) Details where key was backed up
         * 
         * @return builder
         * 
         */
        public Builder restoreFromObjectStore(KeyRestoreFromObjectStoreArgs restoreFromObjectStore) {
            return restoreFromObjectStore(Output.of(restoreFromObjectStore));
        }

        /**
         * @param restoreTrigger (Updatable) An optional property when flipped triggers restore from restore option provided in config file.
         * 
         * @return builder
         * 
         */
        public Builder restoreTrigger(@Nullable Output<Boolean> restoreTrigger) {
            $.restoreTrigger = restoreTrigger;
            return this;
        }

        /**
         * @param restoreTrigger (Updatable) An optional property when flipped triggers restore from restore option provided in config file.
         * 
         * @return builder
         * 
         */
        public Builder restoreTrigger(Boolean restoreTrigger) {
            return restoreTrigger(Output.of(restoreTrigger));
        }

        /**
         * @param timeOfDeletion (Updatable) An optional property for the deletion time of the key, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeOfDeletion(@Nullable Output<String> timeOfDeletion) {
            $.timeOfDeletion = timeOfDeletion;
            return this;
        }

        /**
         * @param timeOfDeletion (Updatable) An optional property for the deletion time of the key, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeOfDeletion(String timeOfDeletion) {
            return timeOfDeletion(Output.of(timeOfDeletion));
        }

        public KeyArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.displayName = Objects.requireNonNull($.displayName, "expected parameter 'displayName' to be non-null");
            $.keyShape = Objects.requireNonNull($.keyShape, "expected parameter 'keyShape' to be non-null");
            $.managementEndpoint = Objects.requireNonNull($.managementEndpoint, "expected parameter 'managementEndpoint' to be non-null");
            return $;
        }
    }

}
