// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FileStorage.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MountTargetKerberosArgs extends com.pulumi.resources.ResourceArgs {

    public static final MountTargetKerberosArgs Empty = new MountTargetKerberosArgs();

    /**
     * (Updatable) Version of the keytab Secret in the Vault to use as a backup.
     * 
     */
    @Import(name="backupKeyTabSecretVersion")
    private @Nullable Output<Integer> backupKeyTabSecretVersion;

    /**
     * @return (Updatable) Version of the keytab Secret in the Vault to use as a backup.
     * 
     */
    public Optional<Output<Integer>> backupKeyTabSecretVersion() {
        return Optional.ofNullable(this.backupKeyTabSecretVersion);
    }

    /**
     * (Updatable) Version of the keytab Secret in the Vault to use.
     * 
     */
    @Import(name="currentKeyTabSecretVersion")
    private @Nullable Output<Integer> currentKeyTabSecretVersion;

    /**
     * @return (Updatable) Version of the keytab Secret in the Vault to use.
     * 
     */
    public Optional<Output<Integer>> currentKeyTabSecretVersion() {
        return Optional.ofNullable(this.currentKeyTabSecretVersion);
    }

    /**
     * (Updatable) Specifies whether to enable or disable Kerberos.
     * 
     */
    @Import(name="isKerberosEnabled")
    private @Nullable Output<Boolean> isKerberosEnabled;

    /**
     * @return (Updatable) Specifies whether to enable or disable Kerberos.
     * 
     */
    public Optional<Output<Boolean>> isKerberosEnabled() {
        return Optional.ofNullable(this.isKerberosEnabled);
    }

    /**
     * (Updatable) The Kerberos realm that the mount target will join.
     * 
     */
    @Import(name="kerberosRealm", required=true)
    private Output<String> kerberosRealm;

    /**
     * @return (Updatable) The Kerberos realm that the mount target will join.
     * 
     */
    public Output<String> kerberosRealm() {
        return this.kerberosRealm;
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the keytab Secret in the Vault.
     * 
     */
    @Import(name="keyTabSecretId")
    private @Nullable Output<String> keyTabSecretId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the keytab Secret in the Vault.
     * 
     */
    public Optional<Output<String>> keyTabSecretId() {
        return Optional.ofNullable(this.keyTabSecretId);
    }

    private MountTargetKerberosArgs() {}

    private MountTargetKerberosArgs(MountTargetKerberosArgs $) {
        this.backupKeyTabSecretVersion = $.backupKeyTabSecretVersion;
        this.currentKeyTabSecretVersion = $.currentKeyTabSecretVersion;
        this.isKerberosEnabled = $.isKerberosEnabled;
        this.kerberosRealm = $.kerberosRealm;
        this.keyTabSecretId = $.keyTabSecretId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MountTargetKerberosArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MountTargetKerberosArgs $;

        public Builder() {
            $ = new MountTargetKerberosArgs();
        }

        public Builder(MountTargetKerberosArgs defaults) {
            $ = new MountTargetKerberosArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param backupKeyTabSecretVersion (Updatable) Version of the keytab Secret in the Vault to use as a backup.
         * 
         * @return builder
         * 
         */
        public Builder backupKeyTabSecretVersion(@Nullable Output<Integer> backupKeyTabSecretVersion) {
            $.backupKeyTabSecretVersion = backupKeyTabSecretVersion;
            return this;
        }

        /**
         * @param backupKeyTabSecretVersion (Updatable) Version of the keytab Secret in the Vault to use as a backup.
         * 
         * @return builder
         * 
         */
        public Builder backupKeyTabSecretVersion(Integer backupKeyTabSecretVersion) {
            return backupKeyTabSecretVersion(Output.of(backupKeyTabSecretVersion));
        }

        /**
         * @param currentKeyTabSecretVersion (Updatable) Version of the keytab Secret in the Vault to use.
         * 
         * @return builder
         * 
         */
        public Builder currentKeyTabSecretVersion(@Nullable Output<Integer> currentKeyTabSecretVersion) {
            $.currentKeyTabSecretVersion = currentKeyTabSecretVersion;
            return this;
        }

        /**
         * @param currentKeyTabSecretVersion (Updatable) Version of the keytab Secret in the Vault to use.
         * 
         * @return builder
         * 
         */
        public Builder currentKeyTabSecretVersion(Integer currentKeyTabSecretVersion) {
            return currentKeyTabSecretVersion(Output.of(currentKeyTabSecretVersion));
        }

        /**
         * @param isKerberosEnabled (Updatable) Specifies whether to enable or disable Kerberos.
         * 
         * @return builder
         * 
         */
        public Builder isKerberosEnabled(@Nullable Output<Boolean> isKerberosEnabled) {
            $.isKerberosEnabled = isKerberosEnabled;
            return this;
        }

        /**
         * @param isKerberosEnabled (Updatable) Specifies whether to enable or disable Kerberos.
         * 
         * @return builder
         * 
         */
        public Builder isKerberosEnabled(Boolean isKerberosEnabled) {
            return isKerberosEnabled(Output.of(isKerberosEnabled));
        }

        /**
         * @param kerberosRealm (Updatable) The Kerberos realm that the mount target will join.
         * 
         * @return builder
         * 
         */
        public Builder kerberosRealm(Output<String> kerberosRealm) {
            $.kerberosRealm = kerberosRealm;
            return this;
        }

        /**
         * @param kerberosRealm (Updatable) The Kerberos realm that the mount target will join.
         * 
         * @return builder
         * 
         */
        public Builder kerberosRealm(String kerberosRealm) {
            return kerberosRealm(Output.of(kerberosRealm));
        }

        /**
         * @param keyTabSecretId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the keytab Secret in the Vault.
         * 
         * @return builder
         * 
         */
        public Builder keyTabSecretId(@Nullable Output<String> keyTabSecretId) {
            $.keyTabSecretId = keyTabSecretId;
            return this;
        }

        /**
         * @param keyTabSecretId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the keytab Secret in the Vault.
         * 
         * @return builder
         * 
         */
        public Builder keyTabSecretId(String keyTabSecretId) {
            return keyTabSecretId(Output.of(keyTabSecretId));
        }

        public MountTargetKerberosArgs build() {
            if ($.kerberosRealm == null) {
                throw new MissingRequiredPropertyException("MountTargetKerberosArgs", "kerberosRealm");
            }
            return $;
        }
    }

}
