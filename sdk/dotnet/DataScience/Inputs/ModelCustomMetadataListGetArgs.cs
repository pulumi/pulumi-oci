// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Inputs
{

    public sealed class ModelCustomMetadataListGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Category of model metadata which should be null for defined metadata.For custom metadata is should be one of the following values "Performance,Training Profile,Training and Validation Datasets,Training Environment,Reports,Readme,other".
        /// </summary>
        [Input("category")]
        public Input<string>? Category { get; set; }

        /// <summary>
        /// (Updatable) Description of model metadata
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) Is there any artifact present for the metadata.
        /// </summary>
        [Input("hasArtifact")]
        public Input<bool>? HasArtifact { get; set; }

        /// <summary>
        /// (Updatable) Key of the model Metadata. The key can either be user defined or Oracle Cloud Infrastructure defined. List of Oracle Cloud Infrastructure defined keys:
        /// * useCaseType
        /// * libraryName
        /// * libraryVersion
        /// * estimatorClass
        /// * hyperParameters
        /// * testArtifactresults
        /// * fineTuningConfiguration
        /// * deploymentConfiguration
        /// * readme
        /// * license
        /// * evaluationConfiguration
        /// </summary>
        [Input("key")]
        public Input<string>? Key { get; set; }

        [Input("keywords")]
        private InputList<string>? _keywords;

        /// <summary>
        /// (Updatable) list of keywords for searching
        /// </summary>
        public InputList<string> Keywords
        {
            get => _keywords ?? (_keywords = new InputList<string>());
            set => _keywords = value;
        }

        /// <summary>
        /// (Updatable) Allowed values for useCaseType: binary_classification, regression, multinomial_classification, clustering, recommender, dimensionality_reduction/representation, time_series_forecasting, anomaly_detection, topic_modeling, ner, sentiment_analysis, image_classification, object_localization, other
        /// 
        /// Allowed values for libraryName: scikit-learn, xgboost, tensorflow, pytorch, mxnet, keras, lightGBM, pymc3, pyOD, spacy, prophet, sktime, statsmodels, cuml, oracle_automl, h2o, transformers, nltk, emcee, pystan, bert, gensim, flair, word2vec, ensemble, other
        /// </summary>
        [Input("value")]
        public Input<string>? Value { get; set; }

        public ModelCustomMetadataListGetArgs()
        {
        }
        public static new ModelCustomMetadataListGetArgs Empty => new ModelCustomMetadataListGetArgs();
    }
}
