// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AuthTokenState extends com.pulumi.resources.ResourceArgs {

    public static final AuthTokenState Empty = new AuthTokenState();

    /**
     * (Updatable) The description you assign to the auth token during creation. Does not have to be unique, and it&#39;s changeable.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) The description you assign to the auth token during creation. Does not have to be unique, and it&#39;s changeable.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * The detailed status of INACTIVE lifecycleState.
     * 
     */
    @Import(name="inactiveState")
    private @Nullable Output<String> inactiveState;

    /**
     * @return The detailed status of INACTIVE lifecycleState.
     * 
     */
    public Optional<Output<String>> inactiveState() {
        return Optional.ofNullable(this.inactiveState);
    }

    /**
     * The token&#39;s current state.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The token&#39;s current state.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * Date and time the `AuthToken` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return Date and time the `AuthToken` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * Date and time when this auth token will expire, in the format defined by RFC3339. Null if it never expires.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Import(name="timeExpires")
    private @Nullable Output<String> timeExpires;

    /**
     * @return Date and time when this auth token will expire, in the format defined by RFC3339. Null if it never expires.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeExpires() {
        return Optional.ofNullable(this.timeExpires);
    }

    /**
     * The auth token. The value is available only in the response for `CreateAuthToken`, and not for `ListAuthTokens` or `UpdateAuthToken`.
     * 
     */
    @Import(name="token")
    private @Nullable Output<String> token;

    /**
     * @return The auth token. The value is available only in the response for `CreateAuthToken`, and not for `ListAuthTokens` or `UpdateAuthToken`.
     * 
     */
    public Optional<Output<String>> token() {
        return Optional.ofNullable(this.token);
    }

    /**
     * The OCID of the user.
     * 
     */
    @Import(name="userId")
    private @Nullable Output<String> userId;

    /**
     * @return The OCID of the user.
     * 
     */
    public Optional<Output<String>> userId() {
        return Optional.ofNullable(this.userId);
    }

    private AuthTokenState() {}

    private AuthTokenState(AuthTokenState $) {
        this.description = $.description;
        this.inactiveState = $.inactiveState;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
        this.timeExpires = $.timeExpires;
        this.token = $.token;
        this.userId = $.userId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AuthTokenState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AuthTokenState $;

        public Builder() {
            $ = new AuthTokenState();
        }

        public Builder(AuthTokenState defaults) {
            $ = new AuthTokenState(Objects.requireNonNull(defaults));
        }

        /**
         * @param description (Updatable) The description you assign to the auth token during creation. Does not have to be unique, and it&#39;s changeable.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) The description you assign to the auth token during creation. Does not have to be unique, and it&#39;s changeable.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param inactiveState The detailed status of INACTIVE lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder inactiveState(@Nullable Output<String> inactiveState) {
            $.inactiveState = inactiveState;
            return this;
        }

        /**
         * @param inactiveState The detailed status of INACTIVE lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder inactiveState(String inactiveState) {
            return inactiveState(Output.of(inactiveState));
        }

        /**
         * @param state The token&#39;s current state.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The token&#39;s current state.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreated Date and time the `AuthToken` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated Date and time the `AuthToken` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeExpires Date and time when this auth token will expire, in the format defined by RFC3339. Null if it never expires.  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeExpires(@Nullable Output<String> timeExpires) {
            $.timeExpires = timeExpires;
            return this;
        }

        /**
         * @param timeExpires Date and time when this auth token will expire, in the format defined by RFC3339. Null if it never expires.  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeExpires(String timeExpires) {
            return timeExpires(Output.of(timeExpires));
        }

        /**
         * @param token The auth token. The value is available only in the response for `CreateAuthToken`, and not for `ListAuthTokens` or `UpdateAuthToken`.
         * 
         * @return builder
         * 
         */
        public Builder token(@Nullable Output<String> token) {
            $.token = token;
            return this;
        }

        /**
         * @param token The auth token. The value is available only in the response for `CreateAuthToken`, and not for `ListAuthTokens` or `UpdateAuthToken`.
         * 
         * @return builder
         * 
         */
        public Builder token(String token) {
            return token(Output.of(token));
        }

        /**
         * @param userId The OCID of the user.
         * 
         * @return builder
         * 
         */
        public Builder userId(@Nullable Output<String> userId) {
            $.userId = userId;
            return this;
        }

        /**
         * @param userId The OCID of the user.
         * 
         * @return builder
         * 
         */
        public Builder userId(String userId) {
            return userId(Output.of(userId));
        }

        public AuthTokenState build() {
            return $;
        }
    }

}