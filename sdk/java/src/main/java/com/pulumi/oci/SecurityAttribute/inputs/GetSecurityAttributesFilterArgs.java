// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.SecurityAttribute.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSecurityAttributesFilterArgs extends com.pulumi.resources.ResourceArgs {

    public static final GetSecurityAttributesFilterArgs Empty = new GetSecurityAttributesFilterArgs();

    /**
     * The name assigned to the security attribute during creation. This is the security attribute key. The name must be unique within the security attribute namespace and cannot be changed.
     * 
     */
    @Import(name="name", required=true)
    private Output<String> name;

    /**
     * @return The name assigned to the security attribute during creation. This is the security attribute key. The name must be unique within the security attribute namespace and cannot be changed.
     * 
     */
    public Output<String> name() {
        return this.name;
    }

    @Import(name="regex")
    private @Nullable Output<Boolean> regex;

    public Optional<Output<Boolean>> regex() {
        return Optional.ofNullable(this.regex);
    }

    /**
     * The list of allowed values for a security attribute value.
     * 
     */
    @Import(name="values", required=true)
    private Output<List<String>> values;

    /**
     * @return The list of allowed values for a security attribute value.
     * 
     */
    public Output<List<String>> values() {
        return this.values;
    }

    private GetSecurityAttributesFilterArgs() {}

    private GetSecurityAttributesFilterArgs(GetSecurityAttributesFilterArgs $) {
        this.name = $.name;
        this.regex = $.regex;
        this.values = $.values;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSecurityAttributesFilterArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSecurityAttributesFilterArgs $;

        public Builder() {
            $ = new GetSecurityAttributesFilterArgs();
        }

        public Builder(GetSecurityAttributesFilterArgs defaults) {
            $ = new GetSecurityAttributesFilterArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param name The name assigned to the security attribute during creation. This is the security attribute key. The name must be unique within the security attribute namespace and cannot be changed.
         * 
         * @return builder
         * 
         */
        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name The name assigned to the security attribute during creation. This is the security attribute key. The name must be unique within the security attribute namespace and cannot be changed.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        public Builder regex(@Nullable Output<Boolean> regex) {
            $.regex = regex;
            return this;
        }

        public Builder regex(Boolean regex) {
            return regex(Output.of(regex));
        }

        /**
         * @param values The list of allowed values for a security attribute value.
         * 
         * @return builder
         * 
         */
        public Builder values(Output<List<String>> values) {
            $.values = values;
            return this;
        }

        /**
         * @param values The list of allowed values for a security attribute value.
         * 
         * @return builder
         * 
         */
        public Builder values(List<String> values) {
            return values(Output.of(values));
        }

        /**
         * @param values The list of allowed values for a security attribute value.
         * 
         * @return builder
         * 
         */
        public Builder values(String... values) {
            return values(List.of(values));
        }

        public GetSecurityAttributesFilterArgs build() {
            if ($.name == null) {
                throw new MissingRequiredPropertyException("GetSecurityAttributesFilterArgs", "name");
            }
            if ($.values == null) {
                throw new MissingRequiredPropertyException("GetSecurityAttributesFilterArgs", "values");
            }
            return $;
        }
    }

}
