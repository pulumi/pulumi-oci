// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FusionApps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.FusionApps.inputs.FusionEnvironmentAdminUserItemArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class FusionEnvironmentAdminUserState extends com.pulumi.resources.ResourceArgs {

    public static final FusionEnvironmentAdminUserState Empty = new FusionEnvironmentAdminUserState();

    /**
     * The email address for the administrator.
     * 
     */
    @Import(name="emailAddress")
    private @Nullable Output<String> emailAddress;

    /**
     * @return The email address for the administrator.
     * 
     */
    public Optional<Output<String>> emailAddress() {
        return Optional.ofNullable(this.emailAddress);
    }

    /**
     * The administrator&#39;s first name.
     * 
     */
    @Import(name="firstName")
    private @Nullable Output<String> firstName;

    /**
     * @return The administrator&#39;s first name.
     * 
     */
    public Optional<Output<String>> firstName() {
        return Optional.ofNullable(this.firstName);
    }

    /**
     * unique FusionEnvironment identifier
     * 
     */
    @Import(name="fusionEnvironmentId")
    private @Nullable Output<String> fusionEnvironmentId;

    /**
     * @return unique FusionEnvironment identifier
     * 
     */
    public Optional<Output<String>> fusionEnvironmentId() {
        return Optional.ofNullable(this.fusionEnvironmentId);
    }

    /**
     * A page of AdminUserSummary objects.
     * 
     */
    @Import(name="items")
    private @Nullable Output<List<FusionEnvironmentAdminUserItemArgs>> items;

    /**
     * @return A page of AdminUserSummary objects.
     * 
     */
    public Optional<Output<List<FusionEnvironmentAdminUserItemArgs>>> items() {
        return Optional.ofNullable(this.items);
    }

    /**
     * The administrator&#39;s last name.
     * 
     */
    @Import(name="lastName")
    private @Nullable Output<String> lastName;

    /**
     * @return The administrator&#39;s last name.
     * 
     */
    public Optional<Output<String>> lastName() {
        return Optional.ofNullable(this.lastName);
    }

    /**
     * The password for the administrator.
     * 
     */
    @Import(name="password")
    private @Nullable Output<String> password;

    /**
     * @return The password for the administrator.
     * 
     */
    public Optional<Output<String>> password() {
        return Optional.ofNullable(this.password);
    }

    /**
     * The username for the administrator.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="username")
    private @Nullable Output<String> username;

    /**
     * @return The username for the administrator.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> username() {
        return Optional.ofNullable(this.username);
    }

    private FusionEnvironmentAdminUserState() {}

    private FusionEnvironmentAdminUserState(FusionEnvironmentAdminUserState $) {
        this.emailAddress = $.emailAddress;
        this.firstName = $.firstName;
        this.fusionEnvironmentId = $.fusionEnvironmentId;
        this.items = $.items;
        this.lastName = $.lastName;
        this.password = $.password;
        this.username = $.username;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(FusionEnvironmentAdminUserState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private FusionEnvironmentAdminUserState $;

        public Builder() {
            $ = new FusionEnvironmentAdminUserState();
        }

        public Builder(FusionEnvironmentAdminUserState defaults) {
            $ = new FusionEnvironmentAdminUserState(Objects.requireNonNull(defaults));
        }

        /**
         * @param emailAddress The email address for the administrator.
         * 
         * @return builder
         * 
         */
        public Builder emailAddress(@Nullable Output<String> emailAddress) {
            $.emailAddress = emailAddress;
            return this;
        }

        /**
         * @param emailAddress The email address for the administrator.
         * 
         * @return builder
         * 
         */
        public Builder emailAddress(String emailAddress) {
            return emailAddress(Output.of(emailAddress));
        }

        /**
         * @param firstName The administrator&#39;s first name.
         * 
         * @return builder
         * 
         */
        public Builder firstName(@Nullable Output<String> firstName) {
            $.firstName = firstName;
            return this;
        }

        /**
         * @param firstName The administrator&#39;s first name.
         * 
         * @return builder
         * 
         */
        public Builder firstName(String firstName) {
            return firstName(Output.of(firstName));
        }

        /**
         * @param fusionEnvironmentId unique FusionEnvironment identifier
         * 
         * @return builder
         * 
         */
        public Builder fusionEnvironmentId(@Nullable Output<String> fusionEnvironmentId) {
            $.fusionEnvironmentId = fusionEnvironmentId;
            return this;
        }

        /**
         * @param fusionEnvironmentId unique FusionEnvironment identifier
         * 
         * @return builder
         * 
         */
        public Builder fusionEnvironmentId(String fusionEnvironmentId) {
            return fusionEnvironmentId(Output.of(fusionEnvironmentId));
        }

        /**
         * @param items A page of AdminUserSummary objects.
         * 
         * @return builder
         * 
         */
        public Builder items(@Nullable Output<List<FusionEnvironmentAdminUserItemArgs>> items) {
            $.items = items;
            return this;
        }

        /**
         * @param items A page of AdminUserSummary objects.
         * 
         * @return builder
         * 
         */
        public Builder items(List<FusionEnvironmentAdminUserItemArgs> items) {
            return items(Output.of(items));
        }

        /**
         * @param items A page of AdminUserSummary objects.
         * 
         * @return builder
         * 
         */
        public Builder items(FusionEnvironmentAdminUserItemArgs... items) {
            return items(List.of(items));
        }

        /**
         * @param lastName The administrator&#39;s last name.
         * 
         * @return builder
         * 
         */
        public Builder lastName(@Nullable Output<String> lastName) {
            $.lastName = lastName;
            return this;
        }

        /**
         * @param lastName The administrator&#39;s last name.
         * 
         * @return builder
         * 
         */
        public Builder lastName(String lastName) {
            return lastName(Output.of(lastName));
        }

        /**
         * @param password The password for the administrator.
         * 
         * @return builder
         * 
         */
        public Builder password(@Nullable Output<String> password) {
            $.password = password;
            return this;
        }

        /**
         * @param password The password for the administrator.
         * 
         * @return builder
         * 
         */
        public Builder password(String password) {
            return password(Output.of(password));
        }

        /**
         * @param username The username for the administrator.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder username(@Nullable Output<String> username) {
            $.username = username;
            return this;
        }

        /**
         * @param username The username for the administrator.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder username(String username) {
            return username(Output.of(username));
        }

        public FusionEnvironmentAdminUserState build() {
            return $;
        }
    }

}
