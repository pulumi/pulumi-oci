// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSteeringPoliciesFilterArgs extends com.pulumi.resources.ResourceArgs {

    public static final GetSteeringPoliciesFilterArgs Empty = new GetSteeringPoliciesFilterArgs();

    /**
     * A user-friendly name for the answer, unique within the steering policy. An answer&#39;s `name` property can be referenced in `answerCondition` properties of rules using `answer.name`.
     * 
     */
    @Import(name="name", required=true)
    private Output<String> name;

    /**
     * @return A user-friendly name for the answer, unique within the steering policy. An answer&#39;s `name` property can be referenced in `answerCondition` properties of rules using `answer.name`.
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

    @Import(name="values", required=true)
    private Output<List<String>> values;

    public Output<List<String>> values() {
        return this.values;
    }

    private GetSteeringPoliciesFilterArgs() {}

    private GetSteeringPoliciesFilterArgs(GetSteeringPoliciesFilterArgs $) {
        this.name = $.name;
        this.regex = $.regex;
        this.values = $.values;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSteeringPoliciesFilterArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSteeringPoliciesFilterArgs $;

        public Builder() {
            $ = new GetSteeringPoliciesFilterArgs();
        }

        public Builder(GetSteeringPoliciesFilterArgs defaults) {
            $ = new GetSteeringPoliciesFilterArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param name A user-friendly name for the answer, unique within the steering policy. An answer&#39;s `name` property can be referenced in `answerCondition` properties of rules using `answer.name`.
         * 
         * @return builder
         * 
         */
        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name A user-friendly name for the answer, unique within the steering policy. An answer&#39;s `name` property can be referenced in `answerCondition` properties of rules using `answer.name`.
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

        public Builder values(Output<List<String>> values) {
            $.values = values;
            return this;
        }

        public Builder values(List<String> values) {
            return values(Output.of(values));
        }

        public Builder values(String... values) {
            return values(List.of(values));
        }

        public GetSteeringPoliciesFilterArgs build() {
            if ($.name == null) {
                throw new MissingRequiredPropertyException("GetSteeringPoliciesFilterArgs", "name");
            }
            if ($.values == null) {
                throw new MissingRequiredPropertyException("GetSteeringPoliciesFilterArgs", "values");
            }
            return $;
        }
    }

}
