// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsUserUrnietfparamsscimschemasoracleidcsextensionpasswordStateUserApplicablePasswordPolicyArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsUserUrnietfparamsscimschemasoracleidcsextensionpasswordStateUserApplicablePasswordPolicyArgs Empty = new DomainsUserUrnietfparamsscimschemasoracleidcsextensionpasswordStateUserApplicablePasswordPolicyArgs();

    /**
     * (Updatable) A human readable name, primarily used for display purposes.
     * 
     */
    @Import(name="display")
    private @Nullable Output<String> display;

    /**
     * @return (Updatable) A human readable name, primarily used for display purposes.
     * 
     */
    public Optional<Output<String>> display() {
        return Optional.ofNullable(this.display);
    }

    /**
     * (Updatable) PasswordPolicy priority
     * 
     */
    @Import(name="priority")
    private @Nullable Output<Integer> priority;

    /**
     * @return (Updatable) PasswordPolicy priority
     * 
     */
    public Optional<Output<Integer>> priority() {
        return Optional.ofNullable(this.priority);
    }

    /**
     * (Updatable) User Token URI
     * 
     */
    @Import(name="ref")
    private @Nullable Output<String> ref;

    /**
     * @return (Updatable) User Token URI
     * 
     */
    public Optional<Output<String>> ref() {
        return Optional.ofNullable(this.ref);
    }

    /**
     * (Updatable) The value of a X509 certificate.
     * 
     */
    @Import(name="value", required=true)
    private Output<String> value;

    /**
     * @return (Updatable) The value of a X509 certificate.
     * 
     */
    public Output<String> value() {
        return this.value;
    }

    private DomainsUserUrnietfparamsscimschemasoracleidcsextensionpasswordStateUserApplicablePasswordPolicyArgs() {}

    private DomainsUserUrnietfparamsscimschemasoracleidcsextensionpasswordStateUserApplicablePasswordPolicyArgs(DomainsUserUrnietfparamsscimschemasoracleidcsextensionpasswordStateUserApplicablePasswordPolicyArgs $) {
        this.display = $.display;
        this.priority = $.priority;
        this.ref = $.ref;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsUserUrnietfparamsscimschemasoracleidcsextensionpasswordStateUserApplicablePasswordPolicyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsUserUrnietfparamsscimschemasoracleidcsextensionpasswordStateUserApplicablePasswordPolicyArgs $;

        public Builder() {
            $ = new DomainsUserUrnietfparamsscimschemasoracleidcsextensionpasswordStateUserApplicablePasswordPolicyArgs();
        }

        public Builder(DomainsUserUrnietfparamsscimschemasoracleidcsextensionpasswordStateUserApplicablePasswordPolicyArgs defaults) {
            $ = new DomainsUserUrnietfparamsscimschemasoracleidcsextensionpasswordStateUserApplicablePasswordPolicyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param display (Updatable) A human readable name, primarily used for display purposes.
         * 
         * @return builder
         * 
         */
        public Builder display(@Nullable Output<String> display) {
            $.display = display;
            return this;
        }

        /**
         * @param display (Updatable) A human readable name, primarily used for display purposes.
         * 
         * @return builder
         * 
         */
        public Builder display(String display) {
            return display(Output.of(display));
        }

        /**
         * @param priority (Updatable) PasswordPolicy priority
         * 
         * @return builder
         * 
         */
        public Builder priority(@Nullable Output<Integer> priority) {
            $.priority = priority;
            return this;
        }

        /**
         * @param priority (Updatable) PasswordPolicy priority
         * 
         * @return builder
         * 
         */
        public Builder priority(Integer priority) {
            return priority(Output.of(priority));
        }

        /**
         * @param ref (Updatable) User Token URI
         * 
         * @return builder
         * 
         */
        public Builder ref(@Nullable Output<String> ref) {
            $.ref = ref;
            return this;
        }

        /**
         * @param ref (Updatable) User Token URI
         * 
         * @return builder
         * 
         */
        public Builder ref(String ref) {
            return ref(Output.of(ref));
        }

        /**
         * @param value (Updatable) The value of a X509 certificate.
         * 
         * @return builder
         * 
         */
        public Builder value(Output<String> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value (Updatable) The value of a X509 certificate.
         * 
         * @return builder
         * 
         */
        public Builder value(String value) {
            return value(Output.of(value));
        }

        public DomainsUserUrnietfparamsscimschemasoracleidcsextensionpasswordStateUserApplicablePasswordPolicyArgs build() {
            $.value = Objects.requireNonNull($.value, "expected parameter 'value' to be non-null");
            return $;
        }
    }

}