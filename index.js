let express = require('express');
let app = express();

let sqlite = require('sqlite');

const {auth} = require('./middleware/auth.js')

function setupServer(db) {

    // This is a test frontend - uncomment to check it out
    // app.use(express.static('public'));
    
    app.get('/info', auth, (req, res) => {
        res.send('Full stack example');
    });

    // retrieve all unique street names
    app.get('/streets', auth, (req, res) => {
        db.all(`SELECT DISTINCT(name) FROM BikeRackData`)
          .then( data => {
              console.log(data);
              res.send(data);
          });
    });

    app.get('/streets/:street/', auth, (req, res) => {
        let streetName = req.params.street;
        // query based on street
	// NOTE: this is open to SQL injection attack
        db.all(`SELECT * FROM BikeRackData WHERE name = '${streetName}'`)
          .then( data => {
              res.send(data);              
          });
        

    });

    

    let server = app.listen(8080, () => {
        console.log('Server ready', server.address().port);
    });
    
}

sqlite.open('database.sqlite').then( db => {
	//console.log('database opened', db);

    setupServer(db);
    //return db.all('SELECT * from TEST');
    
})