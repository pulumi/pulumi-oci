// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAuthTokensToken {
    /**
     * @return The description you assign to the auth token. Does not have to be unique, and it&#39;s changeable.
     * 
     */
    private String description;
    /**
     * @return The OCID of the auth token.
     * 
     */
    private String id;
    /**
     * @return The detailed status of INACTIVE lifecycleState.
     * 
     */
    private String inactiveState;
    /**
     * @return The token&#39;s current state.
     * 
     */
    private String state;
    /**
     * @return Date and time the `AuthToken` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return Date and time when this auth token will expire, in the format defined by RFC3339. Null if it never expires.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeExpires;
    /**
     * @return The auth token. The value is available only in the response for `CreateAuthToken`, and not for `ListAuthTokens` or `UpdateAuthToken`.
     * 
     */
    private String token;
    /**
     * @return The OCID of the user.
     * 
     */
    private String userId;

    private GetAuthTokensToken() {}
    /**
     * @return The description you assign to the auth token. Does not have to be unique, and it&#39;s changeable.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return The OCID of the auth token.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The detailed status of INACTIVE lifecycleState.
     * 
     */
    public String inactiveState() {
        return this.inactiveState;
    }
    /**
     * @return The token&#39;s current state.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Date and time the `AuthToken` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return Date and time when this auth token will expire, in the format defined by RFC3339. Null if it never expires.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeExpires() {
        return this.timeExpires;
    }
    /**
     * @return The auth token. The value is available only in the response for `CreateAuthToken`, and not for `ListAuthTokens` or `UpdateAuthToken`.
     * 
     */
    public String token() {
        return this.token;
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

    public static Builder builder(GetAuthTokensToken defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String description;
        private String id;
        private String inactiveState;
        private String state;
        private String timeCreated;
        private String timeExpires;
        private String token;
        private String userId;
        public Builder() {}
        public Builder(GetAuthTokensToken defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.description = defaults.description;
    	      this.id = defaults.id;
    	      this.inactiveState = defaults.inactiveState;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeExpires = defaults.timeExpires;
    	      this.token = defaults.token;
    	      this.userId = defaults.userId;
        }

        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetAuthTokensToken", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetAuthTokensToken", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder inactiveState(String inactiveState) {
            if (inactiveState == null) {
              throw new MissingRequiredPropertyException("GetAuthTokensToken", "inactiveState");
            }
            this.inactiveState = inactiveState;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetAuthTokensToken", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetAuthTokensToken", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeExpires(String timeExpires) {
            if (timeExpires == null) {
              throw new MissingRequiredPropertyException("GetAuthTokensToken", "timeExpires");
            }
            this.timeExpires = timeExpires;
            return this;
        }
        @CustomType.Setter
        public Builder token(String token) {
            if (token == null) {
              throw new MissingRequiredPropertyException("GetAuthTokensToken", "token");
            }
            this.token = token;
            return this;
        }
        @CustomType.Setter
        public Builder userId(String userId) {
            if (userId == null) {
              throw new MissingRequiredPropertyException("GetAuthTokensToken", "userId");
            }
            this.userId = userId;
            return this;
        }
        public GetAuthTokensToken build() {
            final var _resultValue = new GetAuthTokensToken();
            _resultValue.description = description;
            _resultValue.id = id;
            _resultValue.inactiveState = inactiveState;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeExpires = timeExpires;
            _resultValue.token = token;
            _resultValue.userId = userId;
            return _resultValue;
        }
    }
}
