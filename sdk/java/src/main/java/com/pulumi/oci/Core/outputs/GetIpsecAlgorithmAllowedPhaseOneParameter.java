// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetIpsecAlgorithmAllowedPhaseOneParameter {
    /**
     * @return Allowed phase two authentication algorithms.
     * 
     */
    private List<String> authenticationAlgorithms;
    /**
     * @return Allowed phase one Diffie-Hellman groups.
     * 
     */
    private List<String> dhGroups;
    /**
     * @return Allowed phase two encryption algorithms.
     * 
     */
    private List<String> encryptionAlgorithms;

    private GetIpsecAlgorithmAllowedPhaseOneParameter() {}
    /**
     * @return Allowed phase two authentication algorithms.
     * 
     */
    public List<String> authenticationAlgorithms() {
        return this.authenticationAlgorithms;
    }
    /**
     * @return Allowed phase one Diffie-Hellman groups.
     * 
     */
    public List<String> dhGroups() {
        return this.dhGroups;
    }
    /**
     * @return Allowed phase two encryption algorithms.
     * 
     */
    public List<String> encryptionAlgorithms() {
        return this.encryptionAlgorithms;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIpsecAlgorithmAllowedPhaseOneParameter defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> authenticationAlgorithms;
        private List<String> dhGroups;
        private List<String> encryptionAlgorithms;
        public Builder() {}
        public Builder(GetIpsecAlgorithmAllowedPhaseOneParameter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.authenticationAlgorithms = defaults.authenticationAlgorithms;
    	      this.dhGroups = defaults.dhGroups;
    	      this.encryptionAlgorithms = defaults.encryptionAlgorithms;
        }

        @CustomType.Setter
        public Builder authenticationAlgorithms(List<String> authenticationAlgorithms) {
            if (authenticationAlgorithms == null) {
              throw new MissingRequiredPropertyException("GetIpsecAlgorithmAllowedPhaseOneParameter", "authenticationAlgorithms");
            }
            this.authenticationAlgorithms = authenticationAlgorithms;
            return this;
        }
        public Builder authenticationAlgorithms(String... authenticationAlgorithms) {
            return authenticationAlgorithms(List.of(authenticationAlgorithms));
        }
        @CustomType.Setter
        public Builder dhGroups(List<String> dhGroups) {
            if (dhGroups == null) {
              throw new MissingRequiredPropertyException("GetIpsecAlgorithmAllowedPhaseOneParameter", "dhGroups");
            }
            this.dhGroups = dhGroups;
            return this;
        }
        public Builder dhGroups(String... dhGroups) {
            return dhGroups(List.of(dhGroups));
        }
        @CustomType.Setter
        public Builder encryptionAlgorithms(List<String> encryptionAlgorithms) {
            if (encryptionAlgorithms == null) {
              throw new MissingRequiredPropertyException("GetIpsecAlgorithmAllowedPhaseOneParameter", "encryptionAlgorithms");
            }
            this.encryptionAlgorithms = encryptionAlgorithms;
            return this;
        }
        public Builder encryptionAlgorithms(String... encryptionAlgorithms) {
            return encryptionAlgorithms(List.of(encryptionAlgorithms));
        }
        public GetIpsecAlgorithmAllowedPhaseOneParameter build() {
            final var _resultValue = new GetIpsecAlgorithmAllowedPhaseOneParameter();
            _resultValue.authenticationAlgorithms = authenticationAlgorithms;
            _resultValue.dhGroups = dhGroups;
            _resultValue.encryptionAlgorithms = encryptionAlgorithms;
            return _resultValue;
        }
    }
}
