// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsUserRoleArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsUserRoleArgs Empty = new DomainsUserRoleArgs();

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
     * (Updatable) A Boolean value indicating the &#39;primary&#39; or preferred attribute value for this attribute. The primary attribute value &#39;true&#39; MUST appear no more than once.
     * 
     */
    @Import(name="primary")
    private @Nullable Output<Boolean> primary;

    /**
     * @return (Updatable) A Boolean value indicating the &#39;primary&#39; or preferred attribute value for this attribute. The primary attribute value &#39;true&#39; MUST appear no more than once.
     * 
     */
    public Optional<Output<Boolean>> primary() {
        return Optional.ofNullable(this.primary);
    }

    /**
     * (Updatable) A label indicating the attribute&#39;s function.
     * 
     */
    @Import(name="type", required=true)
    private Output<String> type;

    /**
     * @return (Updatable) A label indicating the attribute&#39;s function.
     * 
     */
    public Output<String> type() {
        return this.type;
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

    private DomainsUserRoleArgs() {}

    private DomainsUserRoleArgs(DomainsUserRoleArgs $) {
        this.display = $.display;
        this.primary = $.primary;
        this.type = $.type;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsUserRoleArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsUserRoleArgs $;

        public Builder() {
            $ = new DomainsUserRoleArgs();
        }

        public Builder(DomainsUserRoleArgs defaults) {
            $ = new DomainsUserRoleArgs(Objects.requireNonNull(defaults));
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
         * @param primary (Updatable) A Boolean value indicating the &#39;primary&#39; or preferred attribute value for this attribute. The primary attribute value &#39;true&#39; MUST appear no more than once.
         * 
         * @return builder
         * 
         */
        public Builder primary(@Nullable Output<Boolean> primary) {
            $.primary = primary;
            return this;
        }

        /**
         * @param primary (Updatable) A Boolean value indicating the &#39;primary&#39; or preferred attribute value for this attribute. The primary attribute value &#39;true&#39; MUST appear no more than once.
         * 
         * @return builder
         * 
         */
        public Builder primary(Boolean primary) {
            return primary(Output.of(primary));
        }

        /**
         * @param type (Updatable) A label indicating the attribute&#39;s function.
         * 
         * @return builder
         * 
         */
        public Builder type(Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type (Updatable) A label indicating the attribute&#39;s function.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
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

        public DomainsUserRoleArgs build() {
            $.type = Objects.requireNonNull($.type, "expected parameter 'type' to be non-null");
            $.value = Objects.requireNonNull($.value, "expected parameter 'value' to be non-null");
            return $;
        }
    }

}