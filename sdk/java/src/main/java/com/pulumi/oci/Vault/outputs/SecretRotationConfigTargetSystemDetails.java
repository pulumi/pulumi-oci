// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Vault.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class SecretRotationConfigTargetSystemDetails {
    /**
     * @return (Updatable) The unique identifier (OCID) for the autonomous database that Vault Secret connects to.
     * 
     */
    private @Nullable String adbId;
    /**
     * @return (Updatable) The unique identifier (OCID) of the Oracle Cloud Infrastructure Functions that vault secret connects to.
     * 
     */
    private @Nullable String functionId;
    /**
     * @return (Updatable) Unique identifier of the target system that Vault Secret connects to.
     * 
     */
    private String targetSystemType;

    private SecretRotationConfigTargetSystemDetails() {}
    /**
     * @return (Updatable) The unique identifier (OCID) for the autonomous database that Vault Secret connects to.
     * 
     */
    public Optional<String> adbId() {
        return Optional.ofNullable(this.adbId);
    }
    /**
     * @return (Updatable) The unique identifier (OCID) of the Oracle Cloud Infrastructure Functions that vault secret connects to.
     * 
     */
    public Optional<String> functionId() {
        return Optional.ofNullable(this.functionId);
    }
    /**
     * @return (Updatable) Unique identifier of the target system that Vault Secret connects to.
     * 
     */
    public String targetSystemType() {
        return this.targetSystemType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(SecretRotationConfigTargetSystemDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String adbId;
        private @Nullable String functionId;
        private String targetSystemType;
        public Builder() {}
        public Builder(SecretRotationConfigTargetSystemDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.adbId = defaults.adbId;
    	      this.functionId = defaults.functionId;
    	      this.targetSystemType = defaults.targetSystemType;
        }

        @CustomType.Setter
        public Builder adbId(@Nullable String adbId) {

            this.adbId = adbId;
            return this;
        }
        @CustomType.Setter
        public Builder functionId(@Nullable String functionId) {

            this.functionId = functionId;
            return this;
        }
        @CustomType.Setter
        public Builder targetSystemType(String targetSystemType) {
            if (targetSystemType == null) {
              throw new MissingRequiredPropertyException("SecretRotationConfigTargetSystemDetails", "targetSystemType");
            }
            this.targetSystemType = targetSystemType;
            return this;
        }
        public SecretRotationConfigTargetSystemDetails build() {
            final var _resultValue = new SecretRotationConfigTargetSystemDetails();
            _resultValue.adbId = adbId;
            _resultValue.functionId = functionId;
            _resultValue.targetSystemType = targetSystemType;
            return _resultValue;
        }
    }
}
