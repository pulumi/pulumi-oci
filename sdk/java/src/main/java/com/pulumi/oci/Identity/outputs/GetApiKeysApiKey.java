// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetApiKeysApiKey {
    /**
     * @return The key&#39;s fingerprint (e.g., 12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef).
     * 
     */
    private String fingerprint;
    /**
     * @return An Oracle-assigned identifier for the key, in this format: TENANCY_OCID/USER_OCID/KEY_FINGERPRINT.
     * 
     */
    private String id;
    /**
     * @return The detailed status of INACTIVE lifecycleState.
     * 
     */
    private String inactiveStatus;
    /**
     * @return The key&#39;s value.
     * 
     */
    private String keyValue;
    /**
     * @return The API key&#39;s current state.
     * 
     */
    private String state;
    /**
     * @return Date and time the `ApiKey` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The OCID of the user.
     * 
     */
    private String userId;

    private GetApiKeysApiKey() {}
    /**
     * @return The key&#39;s fingerprint (e.g., 12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef).
     * 
     */
    public String fingerprint() {
        return this.fingerprint;
    }
    /**
     * @return An Oracle-assigned identifier for the key, in this format: TENANCY_OCID/USER_OCID/KEY_FINGERPRINT.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The detailed status of INACTIVE lifecycleState.
     * 
     */
    public String inactiveStatus() {
        return this.inactiveStatus;
    }
    /**
     * @return The key&#39;s value.
     * 
     */
    public String keyValue() {
        return this.keyValue;
    }
    /**
     * @return The API key&#39;s current state.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Date and time the `ApiKey` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The OCID of the user.
     * 
     */
    public String userId() {
        return this.userId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetApiKeysApiKey defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String fingerprint;
        private String id;
        private String inactiveStatus;
        private String keyValue;
        private String state;
        private String timeCreated;
        private String userId;
        public Builder() {}
        public Builder(GetApiKeysApiKey defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.fingerprint = defaults.fingerprint;
    	      this.id = defaults.id;
    	      this.inactiveStatus = defaults.inactiveStatus;
    	      this.keyValue = defaults.keyValue;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.userId = defaults.userId;
        }

        @CustomType.Setter
        public Builder fingerprint(String fingerprint) {
            if (fingerprint == null) {
              throw new MissingRequiredPropertyException("GetApiKeysApiKey", "fingerprint");
            }
            this.fingerprint = fingerprint;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetApiKeysApiKey", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder inactiveStatus(String inactiveStatus) {
            if (inactiveStatus == null) {
              throw new MissingRequiredPropertyException("GetApiKeysApiKey", "inactiveStatus");
            }
            this.inactiveStatus = inactiveStatus;
            return this;
        }
        @CustomType.Setter
        public Builder keyValue(String keyValue) {
            if (keyValue == null) {
              throw new MissingRequiredPropertyException("GetApiKeysApiKey", "keyValue");
            }
            this.keyValue = keyValue;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetApiKeysApiKey", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetApiKeysApiKey", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder userId(String userId) {
            if (userId == null) {
              throw new MissingRequiredPropertyException("GetApiKeysApiKey", "userId");
            }
            this.userId = userId;
            return this;
        }
        public GetApiKeysApiKey build() {
            final var _resultValue = new GetApiKeysApiKey();
            _resultValue.fingerprint = fingerprint;
            _resultValue.id = id;
            _resultValue.inactiveStatus = inactiveStatus;
            _resultValue.keyValue = keyValue;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.userId = userId;
            return _resultValue;
        }
    }
}
