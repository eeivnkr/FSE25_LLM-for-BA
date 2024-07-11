
 - **database_files** : The example database files, including the parsed jsons for three projects involved in our work (Busybox, Coreutils, and OpenSSL), and the produced code embeddings (produced by UnixCoder-C embedding model) for later retrieval in RAG.

 - **IDA_python** : The IDA python script to generate json data for further database construction. These python files should be run in the IDA environment.

 - **source_func_matching** : Process the source code and match the source code functions based on function names from the json produced by IDA.

 - **embedding_generation** : Generate the code embeddings (i.e., **.pt** files) using the unixcoder model, based on the json file output by IDA; Retrieve the most similar examples for the targe json, from the particular embeddings (i.e., **.pt** files).

