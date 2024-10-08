// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DbCredentialState extends com.pulumi.resources.ResourceArgs {

    public static final DbCredentialState Empty = new DbCredentialState();

    /**
     * The description you assign to the DB credentials during creation.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return The description you assign to the DB credentials during creation.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * The detailed status of INACTIVE lifecycleState.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return The detailed status of INACTIVE lifecycleState.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * The password for the DB credentials during creation.
     * 
     */
    @Import(name="password")
    private @Nullable Output<String> password;

    /**
     * @return The password for the DB credentials during creation.
     * 
     */
    public Optional<Output<String>> password() {
        return Optional.ofNullable(this.password);
    }

    /**
     * The credential&#39;s current state. After creating a DB credential, make sure its `lifecycleState` changes from CREATING to ACTIVE before using it.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The credential&#39;s current state. After creating a DB credential, make sure its `lifecycleState` changes from CREATING to ACTIVE before using it.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * Date and time the `DbCredential` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return Date and time the `DbCredential` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * Date and time when this credential will expire, in the format defined by RFC3339. Null if it never expires.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Import(name="timeExpires")
    private @Nullable Output<String> timeExpires;

    /**
     * @return Date and time when this credential will expire, in the format defined by RFC3339. Null if it never expires.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeExpires() {
        return Optional.ofNullable(this.timeExpires);
    }

    /**
     * The OCID of the user.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="userId")
    private @Nullable Output<String> userId;

    /**
     * @return The OCID of the user.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> userId() {
        return Optional.ofNullable(this.userId);
    }

    private DbCredentialState() {}

    private DbCredentialState(DbCredentialState $) {
        this.description = $.description;
        this.lifecycleDetails = $.lifecycleDetails;
        this.password = $.password;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
        this.timeExpires = $.timeExpires;
        this.userId = $.userId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DbCredentialState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DbCredentialState $;

        public Builder() {
            $ = new DbCredentialState();
        }

        public Builder(DbCredentialState defaults) {
            $ = new DbCredentialState(Objects.requireNonNull(defaults));
        }

        /**
         * @param description The description you assign to the DB credentials during creation.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description The description you assign to the DB credentials during creation.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param lifecycleDetails The detailed status of INACTIVE lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails The detailed status of INACTIVE lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param password The password for the DB credentials during creation.
         * 
         * @return builder
         * 
         */
        public Builder password(@Nullable Output<String> password) {
            $.password = password;
            return this;
        }

        /**
         * @param password The password for the DB credentials during creation.
         * 
         * @return builder
         * 
         */
        public Builder password(String password) {
            return password(Output.of(password));
        }

        /**
         * @param state The credential&#39;s current state. After creating a DB credential, make sure its `lifecycleState` changes from CREATING to ACTIVE before using it.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The credential&#39;s current state. After creating a DB credential, make sure its `lifecycleState` changes from CREATING to ACTIVE before using it.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreated Date and time the `DbCredential` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated Date and time the `DbCredential` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeExpires Date and time when this credential will expire, in the format defined by RFC3339. Null if it never expires.  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeExpires(@Nullable Output<String> timeExpires) {
            $.timeExpires = timeExpires;
            return this;
        }

        /**
         * @param timeExpires Date and time when this credential will expire, in the format defined by RFC3339. Null if it never expires.  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeExpires(String timeExpires) {
            return timeExpires(Output.of(timeExpires));
        }

        /**
         * @param userId The OCID of the user.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
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
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder userId(String userId) {
            return userId(Output.of(userId));
        }

        public DbCredentialState build() {
            return $;
        }
    }

}
