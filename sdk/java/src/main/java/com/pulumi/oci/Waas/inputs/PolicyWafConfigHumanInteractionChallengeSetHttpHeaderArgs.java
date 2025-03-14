// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class PolicyWafConfigHumanInteractionChallengeSetHttpHeaderArgs extends com.pulumi.resources.ResourceArgs {

    public static final PolicyWafConfigHumanInteractionChallengeSetHttpHeaderArgs Empty = new PolicyWafConfigHumanInteractionChallengeSetHttpHeaderArgs();

    /**
     * (Updatable) The name of the header.
     * 
     */
    @Import(name="name", required=true)
    private Output<String> name;

    /**
     * @return (Updatable) The name of the header.
     * 
     */
    public Output<String> name() {
        return this.name;
    }

    /**
     * (Updatable) The value of the header.
     * 
     */
    @Import(name="value", required=true)
    private Output<String> value;

    /**
     * @return (Updatable) The value of the header.
     * 
     */
    public Output<String> value() {
        return this.value;
    }

    private PolicyWafConfigHumanInteractionChallengeSetHttpHeaderArgs() {}

    private PolicyWafConfigHumanInteractionChallengeSetHttpHeaderArgs(PolicyWafConfigHumanInteractionChallengeSetHttpHeaderArgs $) {
        this.name = $.name;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PolicyWafConfigHumanInteractionChallengeSetHttpHeaderArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PolicyWafConfigHumanInteractionChallengeSetHttpHeaderArgs $;

        public Builder() {
            $ = new PolicyWafConfigHumanInteractionChallengeSetHttpHeaderArgs();
        }

        public Builder(PolicyWafConfigHumanInteractionChallengeSetHttpHeaderArgs defaults) {
            $ = new PolicyWafConfigHumanInteractionChallengeSetHttpHeaderArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param name (Updatable) The name of the header.
         * 
         * @return builder
         * 
         */
        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) The name of the header.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param value (Updatable) The value of the header.
         * 
         * @return builder
         * 
         */
        public Builder value(Output<String> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value (Updatable) The value of the header.
         * 
         * @return builder
         * 
         */
        public Builder value(String value) {
            return value(Output.of(value));
        }

        public PolicyWafConfigHumanInteractionChallengeSetHttpHeaderArgs build() {
            if ($.name == null) {
                throw new MissingRequiredPropertyException("PolicyWafConfigHumanInteractionChallengeSetHttpHeaderArgs", "name");
            }
            if ($.value == null) {
                throw new MissingRequiredPropertyException("PolicyWafConfigHumanInteractionChallengeSetHttpHeaderArgs", "value");
            }
            return $;
        }
    }

}
